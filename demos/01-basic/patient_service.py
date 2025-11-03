"""Sample (intentionally flawed) patient-record service for the BAADIFF demo.

This file mixes a few real HIPAA Security Rule gaps with a few satisfied
controls so the scorecard is realistic. DO NOT use this as a real config.
"""

import hashlib
import logging

import requests
from flask import Flask, session
from flask_login import login_required

app = Flask(__name__)
log = logging.getLogger("patient_service")

# --- GAP: hardcoded credential (BD001, critical) -------------------------- #
DB_PASSWORD = "S3cr3tP@ssw0rd123"
DATABASE_URL = "postgres://phi_admin:S3cr3tP@ssw0rd123@db.internal/patients"

# --- GAP: plaintext HTTP endpoint (BD002, high) --------------------------- #
LAB_RESULTS_API = "http://labs.partner-network.example.com/v1/results"

# (good) auth marker -> BD007 passes
JWT_ALGO = "RS256"


@app.route("/patient/<pid>")
@login_required
def get_patient(pid):
    # (good) audit logging -> BD006 passes
    log.info("access patient record", extra={"user": session.get("uid")})

    # --- GAP: TLS verification disabled (BD002, high) -------------------- #
    resp = requests.get(f"{LAB_RESULTS_API}/{pid}", verify=False)

    # --- GAP: weak hash of patient identifier (BD003, medium) ----------- #
    weak_key = hashlib.md5(pid.encode()).hexdigest()

    # (good) strong integrity hash present -> BD009 passes
    integrity = hashlib.sha256(resp.content).hexdigest()

    return {"patient": pid, "key": weak_key, "integrity": integrity}
