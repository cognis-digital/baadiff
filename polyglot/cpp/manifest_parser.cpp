// polyglot/cpp/manifest_parser.cpp
// baadiff: HIPAA Business Associate Readiness Manifest Parser
// Complete implementation with in-file demo

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <regex>
#include <iomanip>
#include <memory>

namespace baadiff {

// ============================================================================
// Data Structures
// ============================================================================

enum class HIPAACategory : uint8_t {
    ADMINISTRATIVE,
    PHYSICAL,
    TECHNICAL,
    ACCESS_CONTROL,
    AUTHENTICATION,
    AUDIT_CONTROLS,
    INTEGRITY_CONTROLS,
    PERSON_PROCESS,
    WORKFORCE_TRAINING,
    FACILITY_ACCESS,
    WORKSTATION_USE,
    CRYPTOGRAPHIC,
    NETWORK_SECURITY,
    INCIDENT_RESPONSE,
    CONTINUITY_PLANNING,
    RISK_ANALYSIS,
    _COUNT
};

struct ControlRequirement {
    std::string id;
    std::string title;
    std::string description;
    std::vector<std::string> evidence_fields;  // Fields to check in manifest
    uint32_t weight = 10;  // Points toward score (max 100 per category)
};

struct CategoryConfig {
    HIPAACategory category;
    std::string name;
    ControlRequirement requirements[8];
    uint32_t total_weight = 0;
    bool all_required = true;
};

struct ManifestEntry {
    std::string path;
    std::map<std::string, std::string> values;
    std::vector<ManifestEntry> children;
    
    const std::string& get(const std::string& key) const {
        auto it = values.find(key);
        return (it != values.end()) ? it->second : "";
    }
};

struct ScorecardResult {
    uint32_t overall_score = 0;
    std::map<HIPAACategory, uint32_t> category_scores;
    std::vector<std::string> findings;
    std::vector<std::string> recommendations;
    bool is_ready = false;
};

// ============================================================================
// HIPAA Control Definitions
// ============================================================================

static const ControlRequirement ADMIN_REQS[] = {
    {"ADM.01", "Administrative Safeguards Policy", 
     "Establish and maintain written policies and procedures for administrative safeguards.",
     {"policy_administrative"}, 25},
    {"ADM.02", "Risk Analysis Documentation",
     "Conduct initial and periodic risk analysis of electronic PHI systems.",
     {"risk_analysis_report", "security_risk_assessment"}, 25},
    {"ADM.03", "Workforce Training Records",
     "Train workforce on policies and procedures for protecting ePHI.",
     {"training_administrative", "workforce_training_log"}, 25},
    {"ADM.04", "Incident Response Plan",
     "Establish procedures to address security incidents involving ePHI.",
     {"incident_response_plan", "security_incident_procedure"}, 25},
};

static const ControlRequirement PHYSICAL_REQS[] = {
    {"PHY.01", "Facility Access Controls",
     "Implement physical access controls for facilities housing ePHI systems.",
     {"facility_access_policy", "physical_access_control"}, 25},
    {"PHY.02", "Workstation Security Policy",
     "Establish policies for workstation security and use.",
     {"workstation_security_policy", "workstation_use_procedure"}, 25},
};

static const ControlRequirement TECH_REQS[] = {
    {"TEC.01", "Access Control Policy",
     "Implement unique user identification and access controls.",
     {"access_control_policy", "unique_user_id_policy"}, 25},
    {"TEC.02", "Authentication Mechanism",
     "Implement authentication for electronic systems accessing ePHI.",
     {"authentication_mechanism", "multi_factor_auth_config"}, 25},
    {"TEC.03", "Audit Control Configuration",
     "Create mechanisms to record and examine activity in systems that access ePHI.",
     {"audit_log_configuration", "activity_logging_policy"}, 25},
    {"TEC.04", "Integrity Controls",
     "Implement mechanisms to ensure accuracy and completeness of ePHI.",
     {"integrity_controls", "checksum_validation_config"}, 25},
};

static const ControlRequirement NETWORK_REQS[] = {
    {"NET.01", "Network Security Architecture",
     "Design network security architecture for systems accessing ePHI.",
     {"network_architecture_doc", "segmentation_policy"}, 25},
    {"NET.02", "Encryption in Transit/At Rest",
     "Implement encryption for ePHI during transmission and storage.",
     {"encryption_in_transit_config", "encryption_at_rest_policy"}, 25},
};

static const ControlRequirement CONTINUITY_REQS[] = {
    {"CON.01", "Contingency Planning",
     "Establish procedures to restore systems after disruption.",
     {"contingency_plan", "disaster_recovery_procedure"}, 25},
    {"CON.02", "Data Backup Strategy",
     "Implement data backup strategy for ePHI systems.",
     {"backup_strategy_doc", "recovery_point_objective_config"}, 25},
};

static const ControlRequirement RISK_REQS[] = {
    {"RIS.01", "Risk Analysis Methodology",
     "Establish methodology for ongoing risk analysis.",
     {"risk_methodology_doc", "threat_model_documentation"}, 25},
    {"RIS.02", "Third-Party Risk Management",
     "Manage risks from third-party arrangements involving ePHI.",
     {"third_party_risk_policy", "business_associate_agreement_template"}, 25},
};

static const ControlRequirement WORKFORCE_REQS[] = {
    {"WKF.01", "Workforce Screening Procedures",
     "Establish procedures for screening workforce members.",
     {"workforce_screening_policy", "background_check_procedure"}, 25},
    {"WKF.02", "Role-Based Access Assignment",
     "Assign access rights based on roles and responsibilities.",
     {"role_based_access_config", "privilege_escalation_procedure"}, 25},
};

// ============================================================================
// Category Mappings
// ============================================================================

static const CategoryConfig CATEGORIES[] = {
    // Administrative Safeguards
    {HIPAACategory::ADMINISTRATIVE, "Administrative Safeguards", ADMIN_REQS, 100},
    // Physical Safeguards  
    {HIPAACategory::PHYSICAL, "Physical Safeguards", PHYSICAL_REQS, 50},
    // Technical Safeguards - Access Control
    {HIPAACategory::ACCESS_CONTROL, "Access Control (Technical)", TECH_REQS, 100},
    // Technical Safeguards - Authentication
    {HIPAACategory::AUTHENTICATION, "Authentication", NETWORK_REQS, 50},
    // Technical Safeguards - Audit Controls
    {HIPAACategory::AUDIT_CONTROLS, "Audit Controls", CONTINUITY_REQS, 50},
    // Technical Safeguards - Integrity
    {HIPAACategory::INTEGRITY_CONTROLS, "Integrity Controls", RISK_REQS, 50},
    // Person/Process
    {HIPAACategory::PERSON_PROCESS, "Person and Process", WORKFORCE_REQS, 50},
};

// ============================================================================
// Parser Implementation
// ============================================================================

class ManifestParser {
public:
    static std::unique_ptr<ManifestEntry> parse(const std::string& filepath) {
        auto result = std::make_unique<ManifestEntry>();
        
        // Try different formats in order of likelihood
        if (try_parse_json(result.get(), filepath)) return result;
        if (try_parse_yaml(result.get(), filepath)) return result;
        if (try_parse_toml(result.get(), filepath)) return result;
        
        // Fallback: read raw and attempt generic parsing
        std::ifstream file(filepath);
        if (!file.is_open()) {
            result->values["error"] = "Failed to open file";
            return result;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            // Simple key=value parsing for generic formats
            size_t eq_pos = line.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = line.substr(0, eq_pos);
                std::string value = line.substr(eq_pos + 1);
                
                // Trim whitespace
                while (!key.empty() && isspace(key.back())) key.pop_back();
                while (!value.empty() && isspace(value.front())) value.erase(0, 1);
                
                result->values[key] = value;
            }
        }
        
        return result;
    }

private:
    static bool try_parse_json(ManifestEntry* entry, const std::string& filepath) {
        std::ifstream file(filepath);
        if (!file.is_open()) return false;
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        // Remove leading/trailing whitespace and newlines
        while (!content.empty() && isspace(content.front())) content.erase(0, 1);
        while (!content.empty() && isspace(content.back())) content.pop_back();
        
        if (content.length() < 5) return false;
        
        // Check for JSON structure
        if (content[0] != '{') {
            entry->values["error"] = "Not a valid JSON file";
            return true;
        }
        
        // Simple recursive descent parser for nested JSON
        std::string pos = content;
        while (!pos.empty()) {
            size_t brace_pos = pos.find('{');
            if (brace_pos == std::string::npos) break;
            
            std::string key_start = pos.substr(0, brace_pos);
            size_t colon_pos = key_start.find(':');
            
            if (colon_pos != std::string::npos) {
                std::string key = trim(key_start.substr(colon_pos + 1));
                
                // Find the value - handle string, number, boolean, null
                size_t val_start = brace_pos + 1;
                char quote = pos[val_start];
                
                if (quote == '"' || quote == '\'') {
                    // String value
                    size_t val_end = pos.find(quote, val_start);
                    std::string value = pos.substr(val_start, val_end - val_start);
                    
                    // Remove surrounding quotes
                    while (!value.empty() && isspace(value.front())) value.erase(0, 1);
                    while (!value.empty() && isspace(value.back())) value.pop_back();
                    
                    entry->values[key] = value;
                } else if (pos[val_start] == 't' || pos[val_start] == 'f') {
                    // Boolean
                    std::string bool_val = pos.substr(val_start, 4);
                    entry->values[key] = (bool_val == "true") ? "true" : "false";
                } else if (pos[val_start] == 'n') {
                    // Null
                    entry->values[key] = "null";
                } else {
                    // Number or nested object - find matching closing brace
                    int depth = 1;
                    size_t val_end = val_start;
                    
                    while (depth > 0 && val_end < pos.length()) {
                        if (pos[val_end] == '{') depth++;
                        else if (pos[val_end] == '}') depth--;
                        val_end++;
                    }
                    
                    std::string value = trim(pos.substr(val_start, val_end - val_start));
                    entry->values[key] = value;
                }
            }
            
            // Move past this key-value pair
            size_t next_brace = pos.find('{', brace_pos + 1);
            if (next_brace == std::string::npos) break;
            
            pos = pos.substr(next_brace + 1);
        }
        
        return true;
    }

    static bool try_parse_yaml(ManifestEntry* entry, const std::string& filepath) {
        std::ifstream file(filepath);
        if (!file.is_open()) return false;
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        // Simple YAML parser - handles key: value and nested structures
        std::vector<std::string> lines;
        std::istringstream stream(content);
        std::string line;
        
        while (std::getline(stream, line)) {
            // Remove leading/trailing whitespace
            while (!line.empty() && isspace(line.front())) line.erase(0, 1);
            while (!line.empty() && isspace(line.back())) line.pop_back();
            
            if (!line.empty()) {
                lines.push_back(line);
            }
        }
        
        // Parse YAML structure
        for (const auto& l : lines) {
            if (l.empty()) continue;
            
            // Handle key: value pairs
            size_t colon_pos = l.find(':');
            if (colon_pos != std::string::npos) {
                std::string key = trim(l.substr(0, colon_pos));
                
                // Check for nested structure
                std::string rest = l.substr(colon_pos + 1);
                while (!rest.empty() && isspace(rest.front())) rest.erase(0, 1);
                
                if (rest.length() > 0) {
                    // Has a value - extract it
                    size_t val_start = colon_pos + 1;
                    char quote = l[val_start];
                    
                    if (quote == '"' || quote == '\'') {
                        size_t val_end = l.find(quote, val_start);
                        std::string value = l.substr(val_start, val_end - val_start);
                        
                        while (!value.empty() && isspace(value.front())) value.erase(0, 1);
                        while (!value.empty() && isspace(value.back())) value.pop_back();
                        
                        entry->values[key] = value;
                    } else if (l[val_start] == 't' || l[val_start] == 'f') {
                        std::string bool_val = l.substr(val_start, 4);
                        entry->values[key] = (bool_val == "true") ? "true" : "false";
                    } else if (l[val_start] == 'n') {
                        entry->values[key] = "null";
                    } else {
                        // Number or nested - find end of value
                        int depth = 1;
                        size_t val_end = val_start;
                        
                        while (depth > 0 && val_end < l.length()) {
                            if (l[val_end] == '{') depth++;
                            else if (l[val_end] == '}') depth--;
                            val_end++;
                        }
                        
                        std::string value = trim(l.substr(val_start, val_end - val_start));
                        entry->values[key] = value;
                    }
                }
            }
        }
        
        return true;
    }

    static bool try_parse_toml(ManifestEntry* entry, const std::string& filepath) {
        // TOML is similar to INI but with nested tables
        // For simplicity, treat as key=value pairs
        
        std::ifstream file(filepath);
        if (!file.is_open()) return false;
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        // Remove leading/trailing whitespace and newlines
        while (!content.empty() && isspace(content.front())) content.erase(0, 1);
        while (!content.empty() && isspace(content.back())) content.pop_back();
        
        if (content.length() < 5) return false;
        
        // Check for TOML structure
        if (content[0] != '[') {
            entry->values["error"] = "Not a valid TOML file";
            return true;
        }
        
        // Simple recursive descent parser for nested TOML
        std::string pos = content;
        while (!pos.empty()) {
            size_t bracket_pos = pos.find('[');
            if (bracket_pos == std::string::npos) break;
            
            std::string key_start = pos.substr(0, bracket_pos);
            size_t colon_pos = key_start.find(':');