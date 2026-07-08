/*
 * polyglot/c/manifest_parser.c
 * 
 * baadiff - HIPAA Security Rule Gap Scanner & Business Associate Readiness Tool
 * 
 * A complete, self-contained manifest parser that:
 *   1) Parses YAML-style infrastructure manifests
 *   2) Evaluates against HIPAA Security Rule requirements
 *   3) Generates a Business Associate readiness scorecard
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define MAX_LINE 4096
#define MAX_ENTRIES 1024
#define MAX_RULES 256
#define MAX_SCORECARD_LINES 8192

/* ============================================================================
 * Data Structures
 * ============================================================================ */

typedef enum {
    TYPE_STRING,
    TYPE_BOOL,
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_ARRAY
} ValueType;

typedef struct {
    char key[256];
    ValueType type;
    union {
        char str[MAX_LINE];
        bool bval;
        int ival;
        float fval;
        int *arr;
    } value;
} YamlNode;

typedef enum {
    HIPAA_ADMIN,
    HIPAA_PHYSICAL,
    HIPAA_TECHNICAL
} HipaaCategory;

typedef struct {
    char id[64];
    char description[256];
    HipaaCategory category;
    bool is_required;  // Must be present for full compliance
    float weight;      // Contribution to score (0-100)
} RuleDef;

typedef struct {
    char field_path[512];   // e.g., "encryption.transit.enabled"
    RuleDef rule;
    int status;             // 0=unknown, 1=present, 2=active, 3=partial
    float confidence;       // 0.0-1.0 based on evidence strength
} CheckResult;

typedef struct {
    char name[256];
    HipaaCategory category;
    RuleDef rule;
    CheckResult check_result;
    int points_earned;
    int max_points;
} ScorecardRow;

/* ============================================================================
 * Global State (for demo purposes - would be thread-local in production)
 * ============================================================================ */

static YamlNode g_root_node = {0};
static RuleDef g_rules[MAX_RULES];
static CheckResult g_results[MAX_ENTRIES];
static int g_rule_count = 0;
static ScorecardRow g_scorecard[MAX_SCORECARD_LINES];
static int g_card_rows = 0;

/* ============================================================================
 * YAML Parser Implementation
 * ============================================================================ */

static YamlNode* yaml_create_node() {
    YamlNode *node = (YamlNode*)malloc(sizeof(YamlNode));
    if (!node) return NULL;
    
    node->key[0] = '\0';
    node->type = TYPE_STRING;
    node->value.str[0] = '\0';
    node->value.bval = false;
    node->value.ival = 0;
    node->value.fval = 0.0f;
    node->value.arr = NULL;
    
    return node;
}

static YamlNode* yaml_find_key(YamlNode *parent, const char *key) {
    if (!parent || !key) return NULL;
    
    /* Simple linear search for demo */
    for (int i = 0; parent[i].type != TYPE_ARRAY && parent[i].type != TYPE_STRING; i++) {
        if (strcmp(parent[i].key, key) == 0) {
            return &parent[i];
        }
    }
    
    /* If we have an array, search within */
    for (int i = 0; parent[i].type == TYPE_ARRAY && parent[i].arr != NULL; i++) {
        YamlNode *child = parent[i].arr;
        if (!child) continue;
        
        while (child->type != TYPE_STRING && child->type != TYPE_ARRAY) {
            if (strcmp(child->key, key) == 0) {
                return child;
            }
            child++;
        }
    }
    
    return NULL;
}

static bool yaml_parse_value(YamlNode *node, const char *line, int pos) {
    /* Skip whitespace */
    while (pos < strlen(line) && isspace((unsigned char)line[pos])) pos++;
    
    if (pos >= strlen(line)) return false;
    
    /* Parse boolean values */
    if (strncmp(&line[pos], "true", 4) == 0 || 
        strncmp(&line[pos], "yes", 3) == 0 ||
        strncmp(&line[pos], "on", 2) == 0) {
        node->type = TYPE_BOOL;
        node->value.bval = true;
        pos += 4;
        return true;
    }
    
    if (strncmp(&line[pos], "false", 5) == 0 || 
        strncmp(&line[pos], "no", 2) == 0 ||
        strncmp(&line[pos], "off", 3) == 0) {
        node->type = TYPE_BOOL;
        node->value.bval = false;
        pos += 5;
        return true;
    }
    
    /* Parse integer */
    if (isdigit((unsigned char)line[pos]) || line[pos] == '-') {
        char *endptr;
        long val = strtol(&line[pos], &endptr, 10);
        node->type = TYPE_INT;
        node->value.ival = (int)val;
        pos += endptr - &line[pos];
        return true;
    }
    
    /* Parse float */
    if (isdigit((unsigned char)line[pos]) || line[pos] == '.' || 
        (line[pos] == '-' && isdigit((unsigned char)line[pos+1]))) {
        char *endptr;
        double val = strtod(&line[pos], &endptr);
        node->type = TYPE_FLOAT;
        node->value.fval = (float)val;
        pos += endptr - &line[pos];
        return true;
    }
    
    /* Parse string */
    if (line[pos] == '"' || line[pos] == '\'') {
        char quote = line[pos];
        int len = 0;
        while (pos < strlen(line) && line[pos] != quote) {
            node->value.str[len++] = line[pos++];
        }
        if (pos < strlen(line)) pos++; /* Skip closing quote */
        node->type = TYPE_STRING;
        node->value.str[len] = '\0';
        return true;
    }
    
    return false;
}

static int yaml_parse_line(YamlNode *parent, const char *line) {
    if (!parent || !line || strlen(line) == 0) return 0;
    
    /* Skip empty lines and comments */
    while (isspace((unsigned char)line[0])) line++;
    if (strlen(line) == 0 || line[0] == '#') return 1;
    
    /* Parse key-value pairs */
    YamlNode *child = yaml_find_key(parent, "root");
    if (!child) {
        child = &parent->value.arr[0];
        parent->type = TYPE_ARRAY;
        parent->arr = (YamlNode*)malloc(sizeof(YamlNode));
        if (!parent->arr) return 1;
    }
    
    int pos = 0;
    while (pos < strlen(line)) {
        char key[256] = {0};
        char val[MAX_LINE] = {0};
        
        /* Extract key */
        if (line[pos] == '-') {
            pos++;
            while (pos < strlen(line) && line[pos] != ':' && !isspace((unsigned char)line[pos])) {
                key[0] = line[pos++];
            }
        } else {
            break; /* End of this level */
        }
        
        if (!key[0]) break;
        
        /* Extract value */
        pos++;
        while (pos < strlen(line) && line[pos] != ':' && !isspace((unsigned char)line[pos])) {
            val[0] = line[pos++];
        }
        
        /* Trim trailing colon and whitespace */
        if (val[strlen(val)-1] == ':') val[strlen(val)-1] = '\0';
        
        /* Create new node */
        YamlNode *new_node = yaml_create_node();
        if (!new_node) return 1;
        
        strncpy(new_node->key, key, sizeof(key));
        new_node->key[sizeof(key)-1] = '\0';
        
        if (strlen(val) > 0 && !yaml_parse_value(new_node, val, 0)) {
            /* Default to string */
            new_node->type = TYPE_STRING;
            strncpy(new_node->value.str, val, sizeof(val));
            new_node->value.str[sizeof(val)-1] = '\0';
        }
        
        if (child->type == TYPE_ARRAY) {
            child++;
            /* Expand array */
            int cap = parent->arr ? 4 : 2;
            while ((int)(child - &parent->value.arr[0]) >= cap) {
                YamlNode *exp = (YamlNode*)realloc(parent->arr, sizeof(YamlNode) * (cap + 1));
                if (!exp) return 1;
                parent->arr = exp;
                cap *= 2;
            }
            child = &parent->value.arr[cap-1];
        } else {
            /* First element - initialize array */
            int cap = 4;
            YamlNode *exp = (YamlNode*)malloc(sizeof(YamlNode) * cap);
            if (!exp) return 1;
            exp[0] = *child;
            parent->type = TYPE_ARRAY;
            parent->arr = exp;
            child = &parent->value.arr[1];
        }
        
        /* Copy data to new position */
        memcpy(child, new_node, sizeof(YamlNode));
        free(new_node);
    }
    
    return 0;
}

static int yaml_parse_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open manifest file '%s'\n", filename);
        return -1;
    }
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        yaml_parse_line(&g_root_node, line);
    }
    
    fclose(fp);
    return 0;
}

/* ============================================================================
 * Rule Definitions - HIPAA Security Rule Requirements
 * ============================================================================ */

static void init_rules(void) {
    int rule_id = 1;
    
    /* Administrative Safeguards (Category: Admin) */
    g_rules[rule_id++] = (RuleDef){
        .id = "ADMIN-001",
        .description = "Administrative Access Control",
        .category = HIPAA_ADMIN,
        .is_required = true,
        .weight = 8.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "ADMIN-002", 
        .description = "Security Incident Response Plan",
        .category = HIPAA_ADMIN,
        .is_required = true,
        .weight = 10.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "ADMIN-003",
        .description = "Risk Analysis Documentation",
        .category = HIPAA_ADMIN,
        .is_required = true,
        .weight = 12.0f
    };
    
    /* Physical Safeguards (Category: Physical) */
    g_rules[rule_id++] = (RuleDef){
        .id = "PHYS-001",
        .description = "Facility Access Controls",
        .category = HIPAA_PHYSICAL,
        .is_required = true,
        .weight = 7.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "PHYS-002",
        .description = "Workstation Security",
        .category = HIPAA_PHYSICAL,
        .is_required = false,
        .weight = 5.0f
    };
    
    /* Technical Safeguards (Category: Technical) */
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-001",
        .description = "Access Control - Unique User IDs",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 15.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-002",
        .description = "Access Control - Emergency Access Procedure",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 12.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-003",
        .description = "Access Control - Inactivity Logout",
        .category = HIPAA_TECHNICAL,
        .is_required = false,
        .weight = 4.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-004",
        .description = "Access Control - Automatic Logoff",
        .category = HIPAA_TECHNICAL,
        .is_required = false,
        .weight = 3.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-005",
        .description = "Access Control - Encryption and Decryption",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 20.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-006",
        .description = "Access Control - Signed/Encrypted Electronic Transmissions",
        .category = HIPAA_TECHNICAL,
        .is_required = false,
        .weight = 8.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-007",
        .description = "Transmission Security - Integrity Controls",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 14.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-008",
        .description = "Transmission Security - Confidentiality/Integrity of Transmission",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 16.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-009",
        .description = "Transmission Security - Encryption in Transit",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 18.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-010",
        .description = "Audit Controls - Activity Logging",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 15.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-011",
        .description = "Audit Controls - Log Review/Analysis",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 12.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-012",
        .description = "Audit Controls - Log Retention",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 8.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-013",
        .description = "Personnel - Authentication",
        .category = HIPAA_TECHNICAL,
        .is_required = true,
        .weight = 14.0f
    };
    
    g_rules[rule_id++] = (RuleDef){
        .id = "TECH-014",
        .description = "Personnel - Risk Analysis for