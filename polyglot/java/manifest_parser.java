package polyglot.java;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.time.Instant;

/**
 * HIPAA Security Rule Gap Scanner for Infrastructure Manifests.
 * Produces a Business Associate readiness scorecard with weighted scoring.
 */
public class ManifestParser {

    private static final double WEIGHT_ACCESS = 25.0;
    private static final double WEIGHT_AUDIT = 15.0;
    private static final double WEIGHT_INTEGRITY = 15.0;
    private static final double WEIGHT_PHYSICAL = 15.0;
    private static final double WEIGHT_TRANSMISSION = 30.0;

    public static class Manifest {
        public String name;
        public Map<String, Object> metadata;
        public List<Map<String, Object>> resources;
        public Map<String, Object> spec;
        
        // Extracted fields for HIPAA evaluation
        private Set<String> users = new HashSet<>();
        private boolean hasEncryptionInTransit = false;
        private boolean hasNetworkPolicies = false;
        private boolean hasAuditLogging = false;
        private boolean hasMfa = false;
        private boolean hasAutoLogoff = false;
        private boolean hasRoleBasedAccess = false;
    }

    public static class Score {
        public int accessControl;
        public int auditControls;
        public int integrityControls;
        public int physicalProcedures;
        public int transmissionSecurity;
        
        public double totalScore; // 0-100
        public String overallStatus;

        public static final int MAX_SCORE = 100;
    }

    /**
     * Parse a manifest file and extract HIPAA-relevant fields.
     */
    public Manifest parseManifest(String path) throws IOException {
        Path p = Paths.get(path);
        String content = Files.readString(p).trim();

        // Detect format
        if (content.contains("apiVersion: v1") || content.contains("kind:")) {
            return parseKubernetes(content);
        } else if (content.contains("\"Type\"") || content.contains("AWSTemplateFormatVersion")) {
            return parseCloudFormation(content);
        } else {
            // Generic YAML fallback
            Yaml yaml = new Yaml();
            Manifest m = yaml.load(content);
            if (m instanceof Manifest) {
                return (Manifest) m;
            }
            throw new IOException("Unrecognized manifest format");
        }
    }

    private Manifest parseKubernetes(String content) throws IOException {
        Yaml yaml = new Yaml();
        
        // Handle multi-document YAML (common in K8s manifests)
        List<Object> docs = yaml.loadAll(content);
        
        Manifest m = new Manifest();
        for (Object doc : docs) {
            if (!(doc instanceof Map)) continue;
            
            Map<String, Object> map = (Map<String, Object>) doc;
            
            // Extract resource name
            if (map.containsKey("metadata")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> meta = (Map<String, Object>) map.get("metadata");
                m.name = extractName(meta);
                
                // Extract users from service accounts or secrets
                extractUsers(map);
            } else if (map.containsKey("spec")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> spec = (Map<String, Object>) map.get("spec");
                m.spec = spec;
                
                // Check for encryption in transit (network policies)
                checkNetworkPolicies(spec);
            }
        }

        return m;
    }

    private Manifest parseCloudFormation(String content) throws IOException {
        Yaml yaml = new Yaml();
        
        @SuppressWarnings("unchecked")
        Map<String, Object> root = (Map<String, Object>) yaml.load(content);
        
        if (!root.containsKey("Resources")) {
            throw new IOException("Invalid CloudFormation manifest");
        }

        Manifest m = new Manifest();
        m.name = extractName((Map<String, Object>) root.get("Metadata"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = (List<Map<String, Object>>) 
                root.getOrDefault("Resources", Collections.emptyList());

        for (Object r : resources) {
            if (!(r instanceof Map)) continue;
            
            @SuppressWarnings("unchecked")
            Map<String, Object> res = (Map<String, Object>) r;
            
            // Extract resource type and properties
            String type = (String) res.getOrDefault("Type", "");
            m.resources.add(res);

            if (type.contains("NetworkSecurityGroup")) {
                checkNetworkPolicies(res);
            } else if (type.contains("SecretsManager") || type.contains("KMS")) {
                m.hasEncryptionInTransit = true;
            } else if (type.contains("IAMRole") || type.contains("User")) {
                extractUsers(res);
            }
        }

        return m;
    }

    private String extractName(Map<String, Object> meta) {
        if (meta.containsKey("name")) {
            return (String) meta.get("name");
        } else if (meta.containsKey("labels")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> labels = (Map<String, Object>) meta.get("labels");
            String name = (String) labels.getOrDefault("app.kubernetes.io/name", "");
            return !name.isEmpty() ? name : "unnamed";
        }
        return "unknown";
    }

    private void extractUsers(Map<String, Object> map) {
        // Check for service accounts
        if (map.containsKey("spec") && 
            ((Map<String, Object>) map.get("spec")).containsKey("serviceAccountName")) {
            String sa = (String) ((Map<String, Object>) map.get("spec")).get("serviceAccountName");
            users.add(sa);
        }

        // Check for secrets containing credentials
        if (map.containsKey("data") && 
            ((Map<String, Object>) map.get("data")).containsKey("password")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> data = (Map<String, Object>) map.get("data");
            users.add(data.keySet().iterator().next()); // The secret name
        }

        // Check for IAM roles/users in CloudFormation
        if (map.containsKey("Properties")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> props = (Map<String, Object>) map.get("Properties");
            
            if (props.containsKey("UserName")) {
                users.add(props.get("UserName").toString());
            } else if (props.containsKey("RoleName")) {
                users.add(props.get("RoleName").toString());
            }
        }
    }

    private void checkNetworkPolicies(Map<String, Object> spec) {
        // Check for NetworkPolicy resources in K8s
        if (spec.containsKey("kind") && 
            "NetworkPolicy".equals(spec.get("kind"))) {
            hasNetworkPolicies = true;
        }

        // Check for VPC/Security Group properties
        if (spec.containsKey("VpcId") || spec.containsKey("SecurityGroupIds")) {
            hasNetworkPolicies = true;
        }
    }

    /**
     * Evaluate HIPAA Security Rule compliance.
     */
    public Score evaluate(Manifest manifest) {
        Score s = new Score();

        // 1. Access Control (25%)
        s.accessControl = evaluateAccessControl(manifest);

        // 2. Audit Controls (15%)
        s.auditControls = evaluateAuditControls(manifest);

        // 3. Integrity Controls (15%)
        s.integrityControls = evaluateIntegrityControls(manifest);

        // 4. Physical Procedures (15%)
        s.physicalProcedures = evaluatePhysicalProcedures(manifest);

        // 5. Transmission Security (30%)
        s.transmissionSecurity = evaluateTransmissionSecurity(manifest);

        // Calculate weighted total score
        double weightedSum = 
            s.accessControl * WEIGHT_ACCESS +
            s.auditControls * WEIGHT_AUDIT +
            s.integrityControls * WEIGHT_INTEGRITY +
            s.physicalProcedures * WEIGHT_PHYSICAL +
            s.transmissionSecurity * WEIGHT_TRANSMISSION;

        s.totalScore = Math.round(weightedSum / 100.0);

        // Determine overall status
        if (s.totalScore >= 90) {
            s.overallStatus = "READY";
        } else if (s.totalScore >= 75) {
            s.overallStatus = "NEEDS_REVIEW";
        } else if (s.totalScore >= 60) {
            s.overallStatus = "AT_RISK";
        } else {
            s.overallStatus = "CRITICAL";
        }

        return s;
    }

    private int evaluateAccessControl(Manifest manifest) {
        int score = 25; // Maximum for this category
        
        if (manifest.hasMfa) {
            score += 10;
        }
        
        if (manifest.hasAutoLogoff) {
            score += 8;
        }

        if (manifest.hasRoleBasedAccess) {
            score += 7;
        }

        // Check for unique user identification
        if (!manifest.users.isEmpty()) {
            score += 5;
        }

        return Math.min(score, 100);
    }

    private int evaluateAuditControls(Manifest manifest) {
        int score = 15;
        
        if (manifest.hasAuditLogging) {
            score += 12;
        }

        // Check for audit-related resources
        for (Object r : manifest.resources) {
            @SuppressWarnings("unchecked")
            Map<String, Object> res = (Map<String, Object>) r;
            
            if (res.containsKey("Type")) {
                String type = ((String) res.get("Type")).toLowerCase();
                if (type.contains("cloudwatchlogs") || 
                    type.contains("audittrail") ||
                    type.contains("s3" + "eventbridge")) {
                    score += 3;
                }
            }
        }

        return Math.min(score, 100);
    }

    private int evaluateIntegrityControls(Manifest manifest) {
        int score = 15;
        
        // Check for checksums or versioning
        if (manifest.spec != null && 
            ((Map<String, Object>) manifest.spec).containsKey("checksum")) {
            score += 8;
        }

        // Check for immutable infrastructure patterns
        if (manifest.resources != null) {
            for (Object r : manifest.resources) {
                @SuppressWarnings("unchecked")
                Map<String, Object> res = (Map<String, Object>) r;
                
                if (res.containsKey("Type")) {
                    String type = ((String) res.get("Type")).toLowerCase();
                    if (type.contains("efs") || 
                        type.contains("s3" + "versioning") ||
                        type.contains("snapshot")) {
                        score += 4;
                    }
                }
            }
        }

        return Math.min(score, 100);
    }

    private int evaluatePhysicalProcedures(Manifest manifest) {
        int score = 15;
        
        // Check for VPC isolation (physical/network boundary)
        if (manifest.hasNetworkPolicies) {
            score += 8;
        }

        // Check for dedicated environments
        if (manifest.spec != null && 
            ((Map<String, Object>) manifest.spec).containsKey("environment")) {
            String env = (String) ((Map<String, Object>) manifest.spec).get("environment");
            if ("production".equals(env) || "prod".equals(env)) {
                score += 7;
            }
        }

        return Math.min(score, 100);
    }

    private int evaluateTransmissionSecurity(Manifest manifest) {
        int score = 30; // Maximum for this category
        
        if (manifest.hasEncryptionInTransit) {
            score += 15;
        }

        // Check for TLS/SSL configuration
        if (manifest.spec != null && 
            ((Map<String, Object>) manifest.spec).containsKey("tls")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> tls = (Map<String, Object>) ((Map<String, Object>) manifest.spec).get("tls");
            
            if (tls.containsKey("version") || tls.containsKey("minVersion")) {
                score += 10;
            }
        }

        // Check for secure ingress patterns
        if (manifest.resources != null) {
            for (Object r : manifest.resources) {
                @SuppressWarnings("unchecked")
                Map<String, Object> res = (Map<String, Object>) r;
                
                if (res.containsKey("Type")) {
                    String type = ((String) res.get("Type")).toLowerCase();
                    if (type.contains("ingress" + "ssl") || 
                        type.contains("alb" + "listener" + "tls")) {
                        score += 5;
                    }
                }
            }
        }

        return Math.min(score, 100);
    }

    /**
     * Generate a human-readable report.
     */
    public String generateReport(Manifest manifest, Score score) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("HIPAA Security Rule Assessment Report\n");
        sb.append("======================================\n");
        sb.append(String.format("Timestamp: %s\n", Instant.now().toString()));
        sb.append(String.format("Manifest: %s\n", manifest.name));
        sb.append("\n");

        // Overall summary
        sb.append(String.format("OVERALL STATUS: %s (%.1f%%)\n", 
                score.overallStatus, score.totalScore));
        sb.append("\n");

        // Detailed breakdown
        sb.append("CATEGORY BREAKDOWN\n");
        sb.append("------------------\n");
        
        String[] categories = {
            "Access Control (25%)",
            "Audit Controls (15%)",
            "Integrity Controls (15%)",
            "Physical Procedures (15%)",
            "Transmission Security (30%)"
        };

        int[] scores = {
            score.accessControl,
            score.auditControls,
            score.integrityControls,
            score.physicalProcedures,
            score.transmissionSecurity
        };

        for (int i = 0; i < categories.length; i++) {
            String status = "PASS";
            if (scores[i] < 75) status = "WARN";
            if (scores[i] < 50) status = "FAIL";
            
            sb.append(String.format("  %-32s: %d/100 [%s]\n", 
                    categories[i], scores[i], status));
        }

        // Findings summary
        sb.append("\nKEY FINDINGS\n");
        sb.append("------------\n");

        List<String> findings = new ArrayList<>();

        if (manifest.hasEncryptionInTransit) {
            findings.add("+ Encryption in transit detected");
        } else {
            findings.add("- No explicit encryption-in-transit configuration found");
        }

        if (manifest.hasNetworkPolicies) {
            findings.add("+ Network policies configured");
        } else {
            findings.add("- Limited network segmentation observed");
        }

        if (!manifest.users.isEmpty()) {
            sb.append(String.format("  Users identified: %d\n", manifest.users.size()));
            for (String u : manifest.users) {
                findings.add(String.format("    * %s", u));
            }
        } else {
            findings.add("- No user/service account inventory found");
        }

        if (manifest.hasAuditLogging) {
            findings.add("+ Audit logging enabled");
        } else {
            findings.add("- Audit logging not explicitly configured");
        }

        // Recommendations
        sb.append("\nRECOMMENDATIONS\n");
        sb.append("---------------\n");

        if (score.totalScore < 90) {
            findings.add(String.format("1. Address %d critical/medium gaps before production deployment", 
                    100 - score.totalScore));
            
            if (!manifest.hasEncryptionInTransit) {
                findings.add("   * Configure TLS for all ingress traffic");
            }
            if (manifest.users.isEmpty()) {
                findings.add("   * Document all service accounts and users");
            }
        } else {
            findings.add(String.format("1. System is ready for HIPAA compliance review (%d%% score)", 
                    score.totalScore));
        }

        sb.append("\n");
        for (String f : findings) {
            sb.append(f).append("\n");
        }

        return sb.toString();
    }

    /**
     * Main entry point with demo functionality.
     */
    public static void main(String[] args) throws Exception {
        // Demo: Parse a sample Kubernetes manifest
        String sampleManifest