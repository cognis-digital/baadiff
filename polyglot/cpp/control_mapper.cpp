#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <iomanip>
#include <memory>
#include <functional>
#include <regex>

// ============================================================================
// DOMAIN MODELS
// ============================================================================

namespace baadiff {

enum class ControlCategory {
    ACCESS_CONTROL,
    AUDIT_CONTROLS,
    INTEGRITY_CONTROLS,
    PERSON_AUTHENTICATION,
    TRANSMISSION_SECURITY,
    AVAILABILITY_CONTROLS,
    CONFIGURATION_MANAGEMENT,
    IDENTIFICATION_AND_ACCESS,
    DATA_PROTECTION,
    NETWORK_SECURITY,
    INCIDENT_RESPONSE,
    RISK_ASSESSMENT,
    CONTINUITY_OF_OPERATIONS,
    OTHER
};

struct Control {
    std::string id;
    std::string title;
    ControlCategory category;
    std::vector<std::string> subcategories;
    std::map<std::string, std::string> attributes;  // key: attribute name, value: expected pattern
    
    bool matches(const std::string& resource_type) const {
        auto it = attributes.find("resource_types");
        if (it != attributes.end()) {
            return std::find(it->second.begin(), it->second.end(), resource_type) 
                   != it->second.end();
        }
        return true;  // Default: match all
    }

    bool matches(const std::string& attribute_value, const std::string& attr_name = "") const {
        auto it = attributes.find(attr_name);
        if (it == attributes.end()) {
            it = attributes.find("value_patterns");
        }
        if (it != attributes.end() && !it->second.empty()) {
            return std::regex_match(attribute_value, 
                                   std::regex(it->second));
        }
        return true;  // Default: match all values
    }

    double get_weight() const {
        int weight = 10;
        if (category == ControlCategory::ACCESS_CONTROL) weight = 95;
        else if (category == ControlCategory::AUDIT_CONTROLS) weight = 90;
        else if (category == ControlCategory::INTEGRITY_CONTROLS) weight = 85;
        else if (category == ControlCategory::PERSON_AUTHENTICATION) weight = 95;
        else if (category == ControlCategory::TRANSMISSION_SECURITY) weight = 90;
        return static_cast<double>(weight);
    }
};

struct Resource {
    std::string type;
    std::map<std::string, std::string> attributes;
    
    bool hasAttribute(const std::string& name) const {
        return attributes.find(name) != attributes.end();
    }
    
    std::string getAttribute(const std::string& name, const std::string& defaultVal = "") const {
        auto it = attributes.find(name);
        return (it == attributes.end()) ? defaultVal : it->second;
    }
};

struct ScanResult {
    std::vector<Resource> resources;
    std::map<std::string, ControlCategory> control_matches;  // resource_type -> category
    
    void addResource(const Resource& r) {
        resources.push_back(r);
    }
    
    void matchControl(const std::string& type, const ControlCategory& cat) {
        if (control_matches.find(type) == control_matches.end()) {
            control_matches[type] = cat;
        } else {
            // Merge categories
            auto existing = control_matches.at(type);
            if (existing != cat) {
                // Mark as multi-category match
                control_matches[type] = ControlCategory::OTHER;
            }
        }
    }
};

// ============================================================================
// DEFAULT CONTROL DEFINITIONS
// ============================================================================

Control createDefaultControls() {
    std::vector<Control> controls;
    
    // Access Control - 164.308(a)(1)
    controls.push_back({
        "AC-01", "Account Management", ControlCategory::ACCESS_CONTROL,
        {"user_accounts"}, {}, 95.0
    });
    
    controls.push_back({
        "AC-02", "Identification and Authentication (Logical)", ControlCategory::ACCESS_CONTROL,
        {"iam_role_arn", "principal_id"}, {}, 90.0
    });
    
    // Audit Controls - 164.308(a)(7)
    controls.push_back({
        "AU-02", "Audit Events", ControlCategory::AUDIT_CONTROLS,
        {"logging_enabled", "audit_logs"}, {}, 85.0
    });
    
    controls.push_back({
        "AU-03", "Content of Audit Record", ControlCategory::AUDIT_CONTROLS,
        {"log_format", "json"}, {}, 80.0
    });
    
    // Integrity Controls - 164.308(a)(9)
    controls.push_back({
        "IA-02", "Integrity (Logical)", ControlCategory::INTEGRITY_CONTROLS,
        {"encryption_at_rest", "checksum"}, {}, 95.0
    });
    
    // Person Authentication - 164.308(a)(3)
    controls.push_back({
        "IA-02", "Identification and Authentication (Physical)", ControlCategory::PERSON_AUTHENTICATION,
        {"mfa_enabled", "sso_provider"}, {}, 95.0
    });
    
    // Transmission Security - 164.308(a)(4)
    controls.push_back({
        "TS-02", "Transmission Confidentiality and Integrity", ControlCategory::TRANSMISSION_SECURITY,
        {"tls_version", "https"}, {}, 90.0
    });
    
    // Availability Controls - 164.308(a)(5)
    controls.push_back({
        "AV-02", "Availability (Logical)", ControlCategory::AVAILABILITY_CONTROLS,
        {"high_availability", "redundancy"}, {}, 85.0
    });
    
    // Configuration Management - 164.308(a)(6)
    controls.push_back({
        "CM-02", "Configuration Change Control (Logical)", ControlCategory::CONFIGURATION_MANAGEMENT,
        {"version_control", "change_management"}, {}, 85.0
    });
    
    // Network Security - 164.308(a)(10)
    controls.push_back({
        "NC-02", "Network (Logical)", ControlCategory::NETWORK_SECURITY,
        {"vpc_cidr", "security_group"}, {}, 90.0
    });
    
    // Data Protection - 164.308(a)(11)
    controls.push_back({
        "DP-02", "Data (Logical)", ControlCategory::DATA_PROTECTION,
        {"encryption_algorithm", "aes_256"}, {}, 95.0
    });
    
    // Incident Response - 164.308(a)(12)
    controls.push_back({
        "IR-02", "Incident Response (Logical)", ControlCategory::INCIDENT_RESPONSE,
        {"alerting_enabled", "monitoring"}, {}, 85.0
    });
    
    // Risk Assessment - 164.308(a)(13)
    controls.push_back({
        "RA-02", "Risk Assessment (Logical)", ControlCategory::RISK_ASSESSMENT,
        {"risk_assessment_frequency", "quarterly"}, {}, 85.0
    });
    
    // Continuity of Operations - 164.308(a)(14)
    controls.push_back({
        "CO-02", "Continuity of Operations (Logical)", ControlCategory::CONTINUITY_OF_OPERATIONS,
        {"disaster_recovery_plan", "backup_frequency"}, {}, 90.0
    });

    return {controls};
}

// ============================================================================
// PARSERS
// ============================================================================

class JsonParser {
public:
    static std::vector<Resource> parse(const std::string& json_content) {
        std::vector<Resource> resources;
        
        // Simple JSON parser for resource arrays
        std::regex resource_regex(R"(\[\s*\{[^}]*\}\s*\])");
        std::smatch match;
        
        while (std::regex_search(json_content, match, resource_regex)) {
            std::string resource_str = match[0];
            
            // Extract type
            std::string type = "unknown";
            auto type_pos = resource_str.find("\"type\"");
            if (type_pos != std::string::npos) {
                auto quote1 = resource_str.find('"', type_pos + 6);
                auto quote2 = resource_str.find('"', quote1 + 1);
                if (quote1 != std::string::npos && quote2 != std::string::npos) {
                    type = resource_str.substr(quote1 + 1, quote2 - quote1 - 1);
                }
            }
            
            // Extract attributes
            Resource r;
            r.type = type;
            
            // Look for common attribute patterns
            std::regex attr_regex(R"("\"([^\"]+)\"?\s*:\s*\"?([^",\]]+)");");
            std::smatch attr_match;
            
            while (std::regex_search(resource_str, attr_match, attr_regex)) {
                if (!attr_match[1].empty() && !attr_match[2].empty()) {
                    r.attributes[attr_match[1].str()] = attr_match[2].str();
                }
            }
            
            resources.push_back(r);
        }
        
        return resources;
    }
    
    static std::vector<Resource> parseFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + filename);
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        return parse(buffer.str());
    }
};

// ============================================================================
// CONTROL MAPPER ENGINE
// ============================================================================

class ControlMapper {
private:
    std::vector<Control> controls;
    
public:
    ControlMapper() : controls(createDefaultControls()) {}
    
    void loadCustomControls(const std::string& filename) {
        // Simple YAML-like parser for custom controls
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open custom controls: " + filename);
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        // Parse control definitions (simplified)
        std::regex ctrl_regex(R"((AC|AU|IA|TS|AV|CM|NC|DP|IR|RA|CO)-\d+).*");
        std::smatch match;
        
        while (std::regex_search(content, match, ctrl_regex)) {
            // Extract category and other details
            Control c;
            
            // Parse ID
            auto id_start = content.find("id:", match.position());
            if (id_start != std::string::npos) {
                auto quote1 = content.find('"', id_start + 3);
                auto quote2 = content.find('"', quote1 + 1);
                if (quote1 != std::string::npos && quote2 != std::string::npos) {
                    c.id = content.substr(quote1 + 1, quote2 - quote1 - 1);
                }
            }
            
            // Parse title
            auto title_start = content.find("title:", match.position());
            if (title_start != std::string::npos) {
                auto quote1 = content.find('"', title_start + 6);
                auto quote2 = content.find('"', quote1 + 1);
                if (quote1 != std::string::npos && quote2 != std::string::npos) {
                    c.title = content.substr(quote1 + 1, quote2 - quote1 - 1);
                }
            }
            
            // Parse category
            auto cat_start = content.find("category:", match.position());
            if (cat_start != std::string::npos) {
                auto quote1 = content.find('"', cat_start + 9);
                auto quote2 = content.find('"', quote1 + 1);
                if (quote1 != std::string::npos && quote2 != std::string::npos) {
                    c.category = parseCategory(content.substr(quote1 + 1, quote2 - quote1 - 1));
                }
            }
            
            // Parse attributes
            auto attr_start = content.find("attributes:", match.position());
            if (attr_start != std::string::npos) {
                auto brace_open = content.find('{', attr_start);
                auto brace_close = content.rfind('}', brace_open);
                if (brace_open != std::string::npos && brace_close != std::string::npos) {
                    c.attributes = parseAttributes(content.substr(brace_open + 1, brace_close - brace_open));
                }
            }
            
            // Parse weight
            auto weight_start = content.find("weight:", match.position());
            if (weight_start != std::string::npos) {
                auto num_end = content.find_first_of(",\n", weight_start);
                if (num_end != std::string::npos) {
                    c.weight = std::stod(content.substr(weight_start + 7, num_end - weight_start - 7));
                }
            }
            
            controls.push_back(c);
        }
    }

private:
    ControlCategory parseCategory(const std::string& cat_str) {
        if (cat_str.find("ACCESS_CONTROL") != std::string::npos) return ControlCategory::ACCESS_CONTROL;
        if (cat_str.find("AUDIT_CONTROLS") != std::string::npos) return ControlCategory::AUDIT_CONTROLS;
        if (cat_str.find("INTEGRITY_CONTROLS") != std::string::npos) return ControlCategory::INTEGRITY_CONTROLS;
        if (cat_str.find("PERSON_AUTHENTICATION") != std::string::npos) return ControlCategory::PERSON_AUTHENTICATION;
        if (cat_str.find("TRANSMISSION_SECURITY") != std::string::npos) return ControlCategory::TRANSMISSION_SECURITY;
        if (cat_str.find("AVAILABILITY_CONTROLS") != std::string::npos) return ControlCategory::AVAILABILITY_CONTROLS;
        if (cat_str.find("CONFIGURATION_MANAGEMENT") != std::string::npos) return ControlCategory::CONFIGURATION_MANAGEMENT;
        if (cat_str.find("IDENTIFICATION_AND_ACCESS") != std::string::npos) return ControlCategory::IDENTIFICATION_AND_ACCESS;
        if (cat_str.find("DATA_PROTECTION") != std::string::npos) return ControlCategory::DATA_PROTECTION;
        if (cat_str.find("NETWORK_SECURITY") != std::string::npos) return ControlCategory::NETWORK_SECURITY;
        if (cat_str.find("INCIDENT_RESPONSE") != std::string::npos) return ControlCategory::INCIDENT_RESPONSE;
        if (cat_str.find("RISK_ASSESSMENT") != std::string::npos) return ControlCategory::RISK_ASSESSMENT;
        if (cat_str.find("CONTINUITY_OF_OPERATIONS") != std::string::npos) return ControlCategory::CONTINUITY_OF_OPERATIONS;
        return ControlCategory::OTHER;
    }

public:
    std::map<std::string, double> mapResources(const std::vector<Resource>& resources) {
        std::map<std::string, double> results;
        
        for (const auto& res : resources) {
            // Check against all controls
            for (const auto& ctrl : controls) {
                if (ctrl.matches(res.type)) {
                    // Check attribute matches
                    bool attr_match = true;
                    for (const auto& [attr_name, pattern] : ctrl.attributes) {
                        if (!res.hasAttribute(attr_name)) {
                            continue;  // Optional attribute
                        }
                        if (!ctrl.matches(res.getAttribute(attr_name), attr_name)) {
                            attr_match = false;
                            break;
                        }
                    }
                    
                    if (attr_match) {
                        results[res.type] += ctrl.get_weight();
                    }
                }
            }
        }
        
        return results;
    }
    
    double calculateScore(const std::map<std::string, double>& matches) {
        if (matches.empty()) return 0.0;
        
        double total = 0.0;
        for (const auto& [type, score] : matches) {
            total += score;
        }
        
        // Normalize to percentage (max theoretical is sum of all control weights)
        double max_score = 0.0;
        for (const auto& ctrl : controls) {
            max_score += ctrl.get_weight();
        }
        
        return (total / max_score