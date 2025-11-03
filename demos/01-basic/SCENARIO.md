# Demo 01 — Basic HIPAA readiness scan

This demo runs BAADIFF against a tiny, deliberately-flawed service config
(`patient_service.py`) that resembles code in a healthcare app touching ePHI.

## What it shows

The sample file contains several real, machine-detectable HIPAA Security Rule
gaps:

- A **hardcoded database password** (BD001 — access control, critical).
- A **plaintext `http://` endpoint** for an external API (BD002 — transmission
  security, high).
- A call to **`requests ... verify=False`** disabling TLS verification (BD002).
- **MD5 hashing** of a patient identifier (BD003 — integrity, medium).

It *does* contain some positive controls, so the scorecard isn't all red:

- `logging.info(...)` — audit controls (BD006 pass).
- `@login_required` / JWT auth markers — authentication (BD007 pass).
- `hashlib.sha256` integrity helper (BD009 pass).

Missing controls also surface as gaps (no encryption-at-rest marker BD005, no
backup/contingency marker BD008).

## How to run

```bash
python -m baadiff scan demos/01-basic/patient_service.py
python -m baadiff scan demos/01-basic/patient_service.py --format json
```

## Expected result

- A **critical** finding (the hardcoded secret) is present, so the service is
  reported as **NOT SHIPPABLE** regardless of the numeric score.
- The process **exits non-zero (1)** — this is the CI gate.
- The JSON output includes `"shippable": false`, a `score` below 80, a
  populated `by_severity` map with at least one `critical`, and both `pass`
  and `fail` findings.
