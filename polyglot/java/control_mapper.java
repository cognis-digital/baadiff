import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Control Mapper for baadiff - HIPAA Security Rule Gap Scanner
 * 
 * Maps infrastructure/config findings to HIPAA controls and produces
 * a Business Associate readiness scorecard.
 */
public class control_mapper {

    // =====================================================================
    // DATA MODELS
    // =====================================================================

    /** Represents a single HIPAA Security Rule control */
    static class HippaaControl {
        String id;              // e.g., "S-01"
        String category;        // Administrative, Physical, Technical
        String subcategory;     // Access Control, Audit Controls, etc.
        String title;           // Human-readable description
        String description;
        int severity;           // 1=High, 2=Medium, 3=Low
        List<String> evidenceTypes = new ArrayList<>();

        public HippaaControl(String id, String category, String subcategory, 
                           String title, String desc, int sev) {
            this.id = id;
            this.category = category;
            this.subcategory = subcategory;
            this.title = title;
            this.description = desc;
            this.severity = sev;
        }

        public boolean matchesEvidence(String evidenceType) {
            return evidenceTypes.contains(evidenceType);
        }
    }

    /** Represents a finding from the infrastructure scan */
    static class Finding {
        String resourceType;    // e.g., "IAM_ROLE", "S3_BUCKET"
        String resourceName;
        Map<String, Object> attributes = new HashMap<>();
        
        public boolean hasAttribute(String key) {
            return attributes.containsKey(key);
        }

        public String getAttributeValue(String key, String defaultValue) {
            return attributes.getOrDefault(key, defaultValue).toString();
        }
    }

    /** Tracks evidence for a single control */
    static class ScorecardEntry {
        HippaaControl control;
        boolean satisfied = false;
        List<String> evidenceSources = new ArrayList<>();
        String confidenceLevel = "LOW";  // LOW, MEDIUM, HIGH
        String notes = "";

        public void addEvidence(String source) {
            if (!evidenceSources.contains(source)) {
                evidenceSources.add(source);
                recalculateConfidence();
            }
        }

        private void recalculateConfidence() {
            int count = evidenceSources.size();
            if (count == 0) confidenceLevel = "LOW";
            else if (count >= 3) confidenceLevel = "HIGH";
            else confidenceLevel = "MEDIUM";
        }

        public boolean isHighConfidence() {
            return confidenceLevel.equals("HIGH");
        }
    }

    // =====================================================================
    // CONFIGURATION & STATE
    // =====================================================================

    static class Config {
        String basePath;
        List<String> configPaths = new ArrayList<>();
        int minEvidenceCountForHighConfidence = 3;
        
        public void addConfigPath(String path) {
            configPaths.add(path);
        }
    }

    // =====================================================================
    // DEFAULT HIPAA CONTROL DEFINITIONS
    // =====================================================================

    static List<HippaaControl> buildDefaultControls() {
        List<HippaaControl> controls = new ArrayList<>();

        // --- ADMINISTRATIVE CONTROLS (400) ---
        
        // 401 - Access and Authentication Management
        controls.add(new HippaaControl(
            "S-001", "Administrative", "Access Control",
            "Unique User Identification",
            "Each user must have a unique identifier for authentication.",
            2,
            Arrays.asList("IAM_ROLE_NAME", "USER_ID", "SERVICE_ACCOUNT")
        ));

        controls.add(new HippaaControl(
            "S-002", "Administrative", "Access Control",
            "Emergency Access Procedure",
            "Establish procedures for emergency access to electronic PHI.",
            1,
            Arrays.asList("ADMIN_ROLE", "EMERGENCY_ACCESS", "ON_CALL_CONTACT")
        ));

        // 402 - Access Review and Certification
        controls.add(new HippaaControl(
            "S-003", "Administrative", "Access Control",
            "Periodic Review of Access Rights",
            "Conduct periodic reviews to ensure access rights are appropriate.",
            1,
            Arrays.asList("ACCESS_REVIEW_SCHEDULE", "PERIODIC_ACCESS_AUDIT")
        ));

        // 403 - Information System Activity Management
        controls.add(new HippaaControl(
            "S-004", "Administrative", "Activity Mgmt",
            "Automatic Logoff",
            "Implement automatic logoff after inactivity period.",
            2,
            Arrays.asList("AUTO_LOGOFF_TIMEOUT", "SESSION_TIMEOUT")
        ));

        // --- TECHNICAL CONTROLS (160) ---

        // 164 - Access Control (Technical)
        controls.add(new HippaaControl(
            "T-001", "Technical", "Access Control",
            "Direct Access Control",
            "Implement direct access control to systems.",
            2,
            Arrays.asList("IAM_POLICY", "ACCESS_LIST", "ALLOWED_IPS")
        ));

        controls.add(new HippaaControl(
            "T-002", "Technical", "Access Control",
            "Indirect Access Control",
            "Implement indirect access control (proxy/gateway).",
            1,
            Arrays.asList("API_GATEWAY", "PROXY_SERVER", "LOAD_BALANCER")
        ));

        // 164 - Audit Controls
        controls.add(new HippaaControl(
            "T-003", "Technical", "Audit Controls",
            "Audit Trail Integrity",
            "Ensure audit trail is protected from tampering.",
            2,
            Arrays.asList("LOG_RETENTION_DAYS", "LOG_ENCRYPTION", "IMMUTABLE_LOGS")
        ));

        // 164 - Integrity (Data)
        controls.add(new HippaaControl(
            "T-004", "Technical", "Integrity",
            "Data Integrity Verification",
            "Implement mechanisms to verify data integrity.",
            2,
            Arrays.asList("CHECKSUM_VERIFICATION", "CRC_CHECKS", "PARITY_BITS")
        ));

        // 164 - Transmission Security
        controls.add(new HippaaControl(
            "T-005", "Technical", "Transmission",
            "Integrity of Data in Transit",
            "Ensure integrity during transmission.",
            2,
            Arrays.asList("TLS_ENABLED", "SSL_CERTIFICATE", "HTTPS_ONLY")
        ));

        // --- PHYSICAL CONTROLS (140) ---

        // 165 - Facility Access Control
        controls.add(new HippaaControl(
            "P-001", "Physical", "Facility Access",
            "Contingency Plan for Physical Access",
            "Establish contingency plan for physical access.",
            2,
            Arrays.asList("FACILITY_SECURITY_LEVEL", "KEY_MANAGEMENT", "BADGE_SYSTEM")
        ));

        // =====================================================================
        // MAPPING LOGIC
        // =====================================================================

    /**
     * Main entry point - scans and generates scorecard.
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== baadiff Control Mapper ===");
        System.out.println();

        // Step 1: Initialize configuration
        Config config = new Config();
        if (args.length > 0) {
            config.basePath = args[0];
        } else {
            System.out.print("Enter base path (or press Enter for current dir): ");
            String input = scanner.nextLine().trim();
            config.basePath = !input.isEmpty() ? input : ".";
        }

        // Step 2: Load/Build controls and scan resources
        List<HippaaControl> controls = buildDefaultControls();
        
        System.out.println("Loaded " + controls.size() + " HIPAA control definitions.");
        System.out.println("Base path: " + config.basePath);
        System.out.println();

        // Step 3: Scan for resources and map to controls
        List<Finding> findings = scanResources(config);
        
        if (findings.isEmpty()) {
            System.out.println("No resources found in: " + config.basePath);
            return;
        }

        System.out.println("Found " + findings.size() + " resources.");
        System.out.println();

        // Step 4: Map findings to controls and calculate scores
        Scorecard scorecard = new Scorecard(controls, config.minEvidenceCountForHighConfidence);
        scorecard.mapFindings(findings);

        // Step 5: Output results
        printScorecard(scorecard);
    }

    /**
     * Scans the base path for configuration files and infrastructure definitions.
     */
    private static List<Finding> scanResources(Config config) {
        List<Finding> findings = new ArrayList<>();
        
        // Common patterns to look for
        String[] patterns = {
            "*.json", "*.yaml", "*.yml", "*.properties",
            "terraform/**/*.tf", "kubernetes/**/*.yaml",
            "iam/**/role.json", "s3/**/bucket.json"
        };

        try {
            File baseDir = new File(config.basePath);
            
            // Find all config files
            for (String pattern : patterns) {
                File[] matches = findFiles(baseDir, pattern);
                if (matches != null && matches.length > 0) {
                    for (File f : matches) {
                        Finding finding = parseConfigFile(f);
                        if (finding != null) {
                            findings.add(finding);
                        }
                    }
                }
            }

        } catch (IOException e) {
            System.err.println("Error scanning resources: " + e.getMessage());
        }

        return findings;
    }

    /** Recursively find files matching a pattern */
    private static File[] findFiles(File baseDir, String pattern) throws IOException {
        if (!baseDir.exists() || !baseDir.isDirectory()) {
            return new File[0];
        }

        File[] matches = baseDir.listFiles(f -> f.getName().matches(pattern));
        
        // If no direct matches, search recursively for common infra files
        if (matches == null || matches.length == 0) {
            String[] recursivePatterns = {
                "**/iam/**", "**/security/**", "**/policy/**"
            };

            for (String rp : recursivePatterns) {
                File[] recursiveMatches = baseDir.listFiles(f -> 
                    f.getPath().matches(rp.replace("**/", "")));
                
                if (recursiveMatches != null && recursiveMatches.length > 0) {
                    return recursiveMatches;
                }
            }
        }

        return matches == null ? new File[0] : matches;
    }

    /** Parse a config file and extract relevant attributes */
    private static Finding parseConfigFile(File configFile) throws IOException {
        String content = Files.readString(configFile.toPath());
        
        // Extract resource type based on filename patterns
        String resourceType = "UNKNOWN";
        if (configFile.getName().contains("iam") || configFile.getName().contains("role")) {
            resourceType = "IAM_ROLE";
        } else if (configFile.getName().contains("s3") || configFile.getName().contains("bucket")) {
            resourceType = "S3_BUCKET";
        } else if (content.contains("\"Policy\"")) {
            resourceType = "POLICY_DOCUMENT";
        }

        // Extract key attributes using regex patterns
        Map<String, Object> attributes = new HashMap<>();

        // Try to extract common fields
        Pattern namePattern = Pattern.compile("\"Name\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = namePattern.matcher(content);
        if (m.find()) {
            attributes.put("name", m.group(1));
        }

        // Extract trust relationships for IAM
        Pattern trustPattern = Pattern.compile("\"TrustRelationships\"\\s*:\\s*(\\[.*?\\])");
        m = trustPattern.matcher(content);
        if (m.find()) {
            attributes.put("trust_relationships", m.group(1));
        }

        // Extract policy statements
        Pattern statementPattern = Pattern.compile("\"Statement\"\\s*:\\s*(\\[.*?\\])");
        m = statementPattern.matcher(content);
        if (m.find()) {
            attributes.put("policy_statements", m.group(1));
        }

        // Extract encryption settings
        Pattern encryptPattern = Pattern.compile("\"Encryption\"|\"ServerSideEncryption\"\\s*:\\s*\"([^\"]+)\"");
        m = encryptPattern.matcher(content);
        if (m.find()) {
            attributes.put("encryption", m.group(1));
        }

        // Extract access patterns
        Pattern allowPattern = Pattern.compile("\"Action\"\\s*:\\s*\"Allow\"");
        int allowCount = 0;
        while (m.find()) {
            allowCount++;
        }
        if (allowCount > 0) {
            attributes.put("allow_statements", allowCount);
        }

        // Extract timeout settings
        Pattern timeoutPattern = Pattern.compile("\"Timeout\"|\"MaxSessionDuration\"\\s*:\\s*(\\d+)");
        m = timeoutPattern.matcher(content);
        if (m.find()) {
            attributes.put("timeout_seconds", Integer.parseInt(m.group(1)));
        }

        return new Finding() {{
            this.resourceType = resourceType;
            this.attributes = attributes;
        }};
    }

    // =====================================================================
    // SCORECARD LOGIC
    // =====================================================================

    static class Scorecard {
        List<HippaaControl> controls;
        int minEvidenceCountForHighConfidence;
        
        Map<String, ScorecardEntry> entries = new HashMap<>();

        public Scorecard(List<HippaaControl> controls, int minEvidence) {
            this.controls = controls;
            this.minEvidenceCountForHighConfidence = minEvidence;
            
            // Initialize entries for each control
            for (HippaaControl c : controls) {
                entries.put(c.id, new ScorecardEntry());
                entries.get(c.id).control = c;
            }
        }

        /** Map findings to relevant controls */
        public void mapFindings(List<Finding> findings) {
            for (Finding f : findings) {
                // Determine which control types this finding might satisfy
                List<String> potentialControls = determinePotentialControls(f);
                
                for (String controlId : potentialControls) {
                    ScorecardEntry entry = entries.get(controlId);
                    if (entry != null && !entry.satisfied) {
                        // Add evidence source
                        String evidenceSource = f.resourceType + ": " + 
                            f.getAttributeValue("name", "<unnamed>");
                        
                        // Determine confidence based on finding attributes
                        int attributeCount = 0;
                        for (Object attr : f.attributes.values()) {
                            if (attr != null && !attr.toString().isEmpty()) {
                                attributeCount++;
                            }
                        }

                        String confidence = "MEDIUM";
                        if (attributeCount >= 2) confidence = "HIGH";
                        
                        entry.addEvidence(evidenceSource);
                        
                        // Mark as satisfied if we have reasonable evidence
                        if (entry.evidenceSources.size() >= 1 && 
                            attributeCount >= 1) {
                            entry.satisfied = true;
                        }
                    }
                }
            }

            // Calculate final scores
            calculateScores();
        }

        /** Determine which controls a finding might satisfy */
        private List<String> determinePotentialControls(Finding f) {
            List<String> potential = new ArrayList<>();
            
            switch (f.resourceType) {
                case "IAM_ROLE":
                    // IAM roles typically relate to access control
                    potential.add("S-001");  // Unique User Identification
                    potential.add("T-001");  // Direct Access Control
                    break;
                    
                case "POLICY_DOCUMENT":
                    // Policy documents often define access rules
                    potential.add("S-002");  // Emergency Access Procedure
                    potential.add("S-003");  // Periodic Review of Access Rights
                    break;
                    
                case "S3_BUCKET":
                    // S3 buckets relate to data integrity and transmission
                    potential.add("T-004");  // Data Integrity Verification
                    potential.add("T-005");  // Integrity of Data in Transit
                    break;
                    
                default:
                    // Generic mapping for unknown resources
                    if (f.getAttributeValue("name", "").toLowerCase().contains("admin")) {
                        potential.add("S-002");
                    } else if (f.getAttributeValue("name", "").toLowerCase().contains("audit") || 
                               f.getAttributeValue("name", "").toLowerCase().contains("log")) {
                        potential.add("T-003");