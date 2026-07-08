/*
 * polyglot/c/control_mapper.c
 * 
 * HIPAA Business Associate Readiness Control Mapper
 * Maps infrastructure manifests against HIPAA Security Rule controls
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE 4096
#define MAX_CONTROLS 256
#define MAX_SCORES 128

/* Control categories from HIPAA Security Rule */
typedef enum {
    CAT_ACCESS_CONTROL,
    CAT_AUDIT_CONTROL,
    CAT_INTEGRITY_CONTROL,
    CAT_AUTHENTICATION,
    CAT_TRANSMISSION_SECURITY,
    CAT_SYSTEM_ACTIVITY,
    CAT_CONFIDENTIALITY_INTACTITY_AVAILABILITY,
    CAT_PERSON_ENTITY_AUTHENTICATION,
    CAT_NETWORK_INFRASTRUCTURE_PROTECTION,
    CAT_DATA_RECOVERY_PROCEDURES,
    CAT_RISK_ANALYSIS,
    CAT_CONTINGENCY_PLAN,
    CAT_IDENTIFICATION_ACCESS_AUTHENTICATION,
    CAT_SYSTEM_ALERTS_LOGGING_AUDIT_TRAIL,
    CAT_INTEGRITY_CHECKSUMS,
    CAT_TRANSMISSION_ENCRYPTION,
    CAT_NETWORK_SEGMENTATION,
    CAT_BACKUP_RECOVERY_PROCEDURES,
    CAT_RISK_ASSESSMENT,
    CAT_INCIDENT_RESPONSE_PLAN,
    _CAT_COUNT
} ControlCategory;

/* Individual control definitions */
typedef struct {
    int id;
    const char *name;
    ControlCategory category;
    const char *description;
} ControlDef;

static ControlDef controls[] = {
    /* 164.308(a)(5) - Access Control */
    {1, "Unique User Identification", CAT_ACCESS_CONTROL,
     "System automatically generates unique user IDs"},
    {2, "Emergency Access Procedure", CAT_ACCESS_CONTROL,
     "Documented procedure for emergency access to electronic PHI"},
    
    /* 164.312(d) - Audit Controls */
    {3, "Audit Control Implementation", CAT_AUDIT_CONTROL,
     "System generates audit logs of access and activity"},
    
    /* 164.312(e) - Integrity Controls */
    {4, "Integrity Controls", CAT_INTEGRITY_CONTROL,
     "Mechanisms to ensure data integrity during transmission"},
    
    /* 164.312(i) - Person and Entity Authentication */
    {5, "Strong Authentication", CAT_AUTHENTICATION,
     "Multi-factor authentication for administrative access"},
    
    /* 164.312(l) - Transmission Security */
    {6, "Transmission Encryption", CAT_TRANSMISSION_SECURITY,
     "Encryption in transit (TLS 1.2+)"},
    
    /* 164.312(n) - System Activity Review */
    {7, "System Activity Review", CAT_SYSTEM_ACTIVITY,
     "Regular review of audit logs and activity"},
    
    /* 164.308(a)(4) - Access Control Policy */
    {8, "Access Control Policy", CAT_ACCESS_CONTROL,
     "Documented policy for access management"},
    
    /* 164.308(a)(5)(ii) - Emergency Access */
    {9, "Emergency Access Procedure", CAT_ACCESS_CONTROL,
     "Procedure for emergency access to ePHI"},
    
    /* 164.312(d)(2) - Audit Log Retention */
    {10, "Audit Log Retention", CAT_AUDIT_CONTROL,
     "Minimum 6 months retention of audit logs"},
};

typedef struct {
    int present;
    int partial;
    int missing;
} ControlScore;

static ControlScore scores[MAX_CONTROLS];

/* Initialize all controls to missing */
static void init_scores(void) {
    for (int i = 0; i < MAX_CONTROLS; i++) {
        scores[i].present = 0;
        scores[i].partial = 0;
        scores[i].missing = 1;
    }
}

/* Parse a simple JSON key-value pair */
static int parse_json_bool(const char *json, const char *key) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    
    if (strstr(json, search)) {
        /* Check for true/false after the key */
        char *after = strstr(json, search);
        if (after && strstr(after, ":true")) return 1;
        if (after && strstr(after, ":false")) return 0;
    }
    return -1;
}

/* Parse a simple JSON string value */
static int parse_json_string(const char *json, const char *key, 
                             char *out, size_t out_size) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    
    char *after = strstr(json, search);
    if (!after) return 0;
    
    /* Find the colon */
    after = strchr(after, ':');
    if (!after) return 0;
    
    /* Extract string value */
    after++;
    while (*after == ' ') after++;
    
    char *start = (char *)out;
    size_t i = 0;
    int in_quotes = 1;
    
    while (*after && i < out_size - 1) {
        if (*after == '"' && !in_quotes) {
            break;
        } else if (*after == '"') {
            in_quotes = !in_quotes;
        }
        
        *start++ = *after++;
        i++;
    }
    
    *start = '\0';
    return 1;
}

/* Parse a simple JSON number */
static int parse_json_number(const char *json, const char *key, 
                            double *out) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    
    char *after = strstr(json, search);
    if (!after) return 0;
    
    after = strchr(after, ':');
    if (!after) return 0;
    
    char *endptr;
    double val = strtod(after + 1, &endptr);
    *out = val;
    return (endptr != after + 1);
}

/* Parse a simple JSON array of strings */
static int parse_json_array(const char *json, const char *key, 
                           char **out, size_t max_items) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    
    char *after = strstr(json, search);
    if (!after) return 0;
    
    after = strchr(after, ':');
    if (!after) return 0;
    
    /* Find the array brackets */
    after++;
    while (*after == ' ') after++;
    
    char *start = (char *)out[0];
    size_t i = 0, j = 0;
    int in_quotes = 1;
    
    while (*after && i < max_items - 1) {
        if (*after == '"' && !in_quotes) {
            /* Start of new string */
            char *str_start = (char *)out[i];
            size_t k = 0;
            
            after++;
            while (*after && *after != '"') {
                str_start[k++] = *after++;
            }
            str_start[k] = '\0';
            i++;
        } else if (*after == '"' || !in_quotes) {
            in_quotes = !in_quotes;
        }
        
        after++;
    }
    
    return (int)i;
}

/* Evaluate a single control against manifest data */
static int evaluate_control(int control_id, const char *manifest_json) {
    ControlDef *def = &controls[control_id - 1];
    int result = -1; /* Unknown/missing */
    
    switch (control_id) {
        case 1: /* Unique User ID */
            if (parse_json_bool(manifest_json, "unique_user_ids") == 1) {
                return 1;
            } else if (parse_json_bool(manifest_json, "auto_generate_uids") == 1) {
                return 1;
            }
            break;
            
        case 2: /* Emergency Access */
            if (parse_json_string(manifest_json, "emergency_access_procedure",
                                 NULL, 0)) {
                return 1;
            } else if (parse_json_bool(manifest_json, "has_emergency_access") == 1) {
                return 1;
            }
            break;
            
        case 3: /* Audit Controls */
            if (parse_json_bool(manifest_json, "audit_enabled") == 1) {
                return 1;
            } else if (parse_json_string(manifest_json, "log_destination",
                                         NULL, 0)) {
                return 1;
            }
            break;
            
        case 4: /* Integrity Controls */
            if (parse_json_bool(manifest_json, "integrity_checks") == 1) {
                return 1;
            } else if (parse_json_string(manifest_json, "checksum_algorithm",
                                         NULL, 0)) {
                return 1;
            }
            break;
            
        case 5: /* Strong Authentication */
            if (parse_json_bool(manifest_json, "mfa_enabled") == 1) {
                return 1;
            } else if (parse_json_string(manifest_json, "auth_method",
                                         NULL, 0)) {
                if (strstr(parse_json_string(manifest_json, "auth_method",
                                             NULL, 0), "multi-factor")) {
                    return 1;
                }
            }
            break;
            
        case 6: /* Transmission Encryption */
            if (parse_json_bool(manifest_json, "tls_enabled") == 1) {
                double tls_version = 0.0;
                parse_json_number(manifest_json, "tls_min_version", &tls_version);
                if (tls_version >= 1.2) return 1;
            } else if (parse_json_bool(manifest_json, "encryption_in_transit") == 1) {
                return 1;
            }
            break;
            
        case 7: /* System Activity Review */
            if (parse_json_number(manifest_json, "log_review_frequency", 
                                 &result)) {
                if (result >= 0.0 && result <= 30.0) { /* Weekly to monthly */
                    return 1;
                }
            } else if (parse_json_bool(manifest_json, "automated_log_review") == 1) {
                return 1;
            }
            break;
            
        case 8: /* Access Control Policy */
            if (parse_json_string(manifest_json, "access_policy_url",
                                 NULL, 0)) {
                return 1;
            } else if (parse_json_bool(manifest_json, "has_access_policy") == 1) {
                return 1;
            }
            break;
            
        case 9: /* Emergency Access Procedure */
            if (parse_json_string(manifest_json, "emergency_procedure_url",
                                 NULL, 0)) {
                return 1;
            } else if (parse_json_bool(manifest_json, "has_emergency_proc") == 1) {
                return 1;
            }
            break;
            
        case 10: /* Audit Log Retention */
            double retention_days = 0.0;
            parse_json_number(manifest_json, "log_retention_days", &retention_days);
            if (retention_days >= 180) {
                return 1;
            } else if (retention_days > 60 && retention_days < 180) {
                return 2; /* Partial */
            }
            break;
            
        default:
            break;
    }
    
    return result;
}

/* Calculate overall readiness score */
static double calculate_readiness_score(void) {
    int total_present = 0;
    int total_partial = 0;
    int total_missing = 0;
    
    for (int i = 0; i < MAX_CONTROLS; i++) {
        if (scores[i].present) {
            total_present++;
        } else if (scores[i].partial) {
            total_partial++;
        } else {
            total_missing++;
        }
    }
    
    double score = 0.0;
    int weighted_total = 0;
    
    for (int i = 0; i < MAX_CONTROLS; i++) {
        if (scores[i].present) {
            weighted_total += 100;
        } else if (scores[i].partial) {
            weighted_total += 50;
        }
    }
    
    score = (double)weighted_total / MAX_CONTROLS;
    return score;
}

/* Generate the readiness report */
static void generate_report(const char *manifest_json, double score) {
    printf("=== HIPAA Business Associate Readiness Scorecard ===\n\n");
    printf("Overall Score: %.1f%%\n", score);
    
    if (score >= 90.0) {
        printf("Rating: READY FOR BUSINESS ASSOCIATE AGREEMENT\n");
    } else if (score >= 75.0) {
        printf("Rating: MOSTLY READY - Minor improvements needed\n");
    } else if (score >= 50.0) {
        printf("Rating: PARTIALLY READY - Significant gaps identified\n");
    } else {
        printf("Rating: NOT READY - Major remediation required\n");
    }
    
    printf("\n--- Control Breakdown ---\n");
    
    for (int i = 0; i < MAX_CONTROLS && controls[i].id > 0; i++) {
        ControlDef *def = &controls[i];
        int s = scores[def->id - 1];
        
        printf("%2d. %-45s ", def->id, def->name);
        
        if (s.present) {
            printf("[PRESENT]");
        } else if (s.partial) {
            printf("[PARTIAL]");
        } else {
            printf("[MISSING]");
        }
    }
    
    printf("\n\n--- Detailed Findings ---\n");
    
    for (int i = 0; i < MAX_CONTROLS && controls[i].id > 0; i++) {
        ControlDef *def = &controls[i];
        int s = scores[def->id - 1];
        
        if (!s.present) {
            printf("\nControl %d: %s\n", def->id, def->name);
            printf("  Status: %s\n", s.partial ? "Partially Implemented" : "Not Found");
            
            /* Provide remediation guidance */
            switch (def->id) {
                case 1:
                    printf("  Remediation: Configure system to auto-generate unique user IDs.\n");
                    break;
                case 2:
                    printf("  Remediation: Document emergency access procedures and test annually.\n");
                    break;
                case 3:
                    printf("  Remediation: Enable audit logging and configure log retention >= 180 days.\n");
                    break;
                case 4:
                    printf("  Remediation: Implement checksum validation for data integrity.\n");
                    break;
                case 5:
                    printf("  Remediation: Deploy multi-factor authentication for admin access.\n");
                    break;
                case 6:
                    printf("  Remediation: Upgrade TLS to minimum version 1.2, preferably 1.3.\n");
                    break;
                default:
                    printf("  Remediation: Review system configuration and documentation.\n");
                    break;
            }
        }
    }
    
    printf("\n--- Input Manifest ---\n");
    printf("%s\n", manifest_json);
}

/* Parse command line arguments */
static int parse_args(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <manifest.json> [--demo]\n", argv[0]);
        return -1;
    }
    
    const char *manifest_file = argv[1];
    int demo_mode = 0;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--demo") == 0) {
            demo_mode = 1;
        } else if (strstr(argv[i], ".json")) {
            manifest_file = argv[i];
        }
    }
    
    return demo_mode;
}

/* Main entry point */
int main(int argc, char *argv[]) {
    init_scores();
    
    int demo_mode = parse_args(argc, argv);
    const char *manifest_json = NULL;
    
    if (demo_mode) {
        /* Demo mode with sample manifest */
        printf("=== BA