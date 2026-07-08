using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace baadiff
{
    /// <summary>
    /// HIPAA Security Rule Control mappings for Kubernetes manifests.
    */
    internal static class HipaaControls
    {
        public const string ACCESS_CONTROL = "AC";
        public const string AUDIT_CONTROLS = "AU";
        public const string INTEGRITY_CONTROLS = "IA";
        public const string PHYSICAL_CONTROLS = "PE";
        public const string NETWORK_CONTROLS = "NE";
        public const string POLICY_MANAGEMENT = "PO";

        // Sample control IDs (Simplified for demo)
        private static readonly Dictionary<string, string> ControlMap = new()
        {
            ["rbac:admin"] = $"{ACCESS_CONTROL}:AC-2",      // Unique user IDs
            ["rbac:service-account"] = $"{ACCESS_CONTROL}:AC-3",  // MFA/least privilege
            ["network:ingress-tls"] = $"{NETWORK_CONTROLS}:NE-4",   // Encryption in transit
            ["logging:audit-logs"] = $"{AUDIT_CONTROLS}:AU-2",      // Logging
            ["secrets:vault-ref"] = $"{INTEGRITY_CONTROLS}:IA-5",   // Integrity validation
        };

        public static string GetControlId(string key) => ControlMap.TryGetValue(key, out var id) ? id : null;
    }

    /// <summary>
    /// Represents a single HIPAA control finding.
    */
    internal class Finding
    {
        public string ControlId { get; set; } = "";
        public string Category => HipaaControls.GetControlId(ControlId) ?? "OTHER";
        public string ResourcePath { get; set; } = "";
        public string Description { get; set; } = "";
        public bool Passes { get; set; }
        public List<string> Evidence { get; set; } = new();

        public override string ToString() => $"{ControlId}: {(Passes ? "PASS" : "FAIL")} - {Description}";
    }

    /// <summary>
    /// Represents a parsed Kubernetes manifest resource.
    */
    internal class K8sResource
    {
        public string Kind { get; set; } = "";
        public string Name { get; set; } = "";
        public Dictionary<string, object>? Metadata { get; set; }
        public Dictionary<string, object>? Spec { get; set; }

        public static K8sResource? Parse(string yamlContent)
        {
            // Simple YAML parser for demo - in production use YamlDotNet or System.Text.Json with custom converters
            var json = JsonSerializer.Deserialize<JsonElement>(yamlContent);
            
            if (json.ValueKind != JsonValueKind.Object || 
                !json.TryGetProperty("kind", out var kindProp) || 
                !json.TryGetProperty("metadata", out var metaProp))
            {
                return null;
            }

            return new K8sResource
            {
                Kind = kindProp.GetString() ?? "",
                Name = metaProp["name"]?.GetString() ?? "",
                Metadata = metaProp.Deserialize<Dictionary<string, object>>()
            };
        }
    }

    /// <summary>
    /// Main HIPAA manifest scanner.
    */
    internal class HipaaScanner
    {
        private readonly List<K8sResource> _resources = new();
        private readonly List<Finding> _findings = new();

        public void AddManifest(string yamlContent)
        {
            var resource = K8sResource.Parse(yamlContent);
            if (resource != null)
                _resources.Add(resource);
        }

        public void Scan()
        {
            // 1. Access Control Checks
            CheckAccessControl();
            
            // 2. Audit Controls Checks  
            CheckAuditControls();
            
            // 3. Network/Encryption Checks
            CheckNetworkSecurity();
            
            // 4. Secret Management
            CheckSecretManagement();

            // Remove duplicates and sort findings
            _findings = _findings.DistinctBy(f => f.ControlId).ToList();
        }

        private void CheckAccessControl()
        {
            var adminRoles = _resources.Where(r => 
                r.Spec?.TryGetValue("rules", out var rules) == true &&
                rules.TryGetProperty("apiGroups", out var apiGroups) &&
                apiGroups.GetString() == "rbac.authorization.k8s.io" &&
                rules.TryGetProperty("verbs", out var verbs) &&
                verbs.GetString() == "admin")
                   .Select(r => r.Name);

            if (adminRoles.Any())
            {
                _findings.Add(new Finding
                {
                    ControlId = $"{HipaaControls.ACCESS_CONTROL}:AC-2",
                    ResourcePath = string.Join(", ", adminRoles),
                    Description = "Potential over-permissive RBAC admin roles detected. Review for least privilege.",
                    Passes = false,
                    Evidence = new() { "Found in: " + string.Join(", ", adminRoles) }
                });
            }

            var serviceAccounts = _resources.Where(r => r.Kind == "ServiceAccount");
            if (serviceAccounts.Any(sa => !sa.Spec?.TryGetValue("secrets", out _) ?? false))
            {
                _findings.Add(new Finding
                {
                    ControlId = $"{HipaaControls.ACCESS_CONTROL}:AC-3",
                    ResourcePath = string.Join(", ", serviceAccounts.Select(r => r.Name)),
                    Description = "Service accounts without secrets. Consider adding token request for MFA-like auth.",
                    Passes = false,
                    Evidence = new() { "Service accounts: " + string.Join(", ", serviceAccounts.Select(r => r.Name)) }
                });
            }
        }

        private void CheckAuditControls()
        {
            var loggingEnabled = _resources.Any(r => 
                r.Kind == "Pod" && 
                r.Spec?.TryGetValue("containers", out var containers) == true &&
                containers.TryGetProperty("image", out _) &&
                (string)r.Spec["containers"]["image"]!.Contains("fluentd") ||
                (string)r.Spec["containers"]["image"]!.Contains("logstash"));

            if (!loggingEnabled)
            {
                _findings.Add(new Finding
                {
                    ControlId = $"{HipaaControls.AUDIT_CONTROLS}:AU-2",
                    ResourcePath = "Cluster-wide",
                    Description = "No fluentd/logstash detected. Audit logging may be incomplete.",
                    Passes = false,
                    Evidence = new() { "Check cluster logging configuration" }
                });
            }

            var auditAnnotations = _resources.Where(r => 
                r.Metadata?.TryGetValue("annotations", out var ann) == true &&
                ann.TryGetProperty("audit-log-enabled", out _) ||
                ann.TryGetProperty("hipaa-audit", out _));

            if (auditAnnotations.Any())
            {
                _findings.Add(new Finding
                {
                    ControlId = $"{HipaaControls.AUDIT_CONTROLS}:AU-3",
                    ResourcePath = string.Join(", ", auditAnnotations.Select(r => r.Name)),
                    Description = "Audit annotations detected - verify they're being consumed.",
                    Passes = true,
                    Evidence = new() { "Found in: " + string.Join(", ", auditAnnotations.Select(r => r.Name)) }
                });
            }
        }

        private void CheckNetworkSecurity()
        {
            var tlsEnabled = _resources.Any(r => 
                r.Kind == "Ingress" &&
                r.Spec?.TryGetValue("tls", out _) == true);

            if (!tlsEnabled)
            {
                _findings.Add(new Finding
                {
                    ControlId = $"{HipaaControls.NETWORK_CONTROLS}:NE-4",
                    ResourcePath = "Cluster-wide Ingress",
                    Description = "Ingress resources may not have TLS configured. Check for plain HTTP.",
                    Passes = false,
                    Evidence = new() { "Review all Ingress CRDs" }
                });
            }

            var networkPolicies = _resources.Where(r => r.Kind == "NetworkPolicy");
            if (networkPolicies.Any())
            {
                _findings.Add(new Finding
                {
                    ControlId = $"{HipaaControls.NETWORK_CONTROLS}:NE-6",
                    ResourcePath = string.Join(", ", networkPolicies.Select(n => n.Name)),
                    Description = "Network policies found. Verify they implement segmentation.",
                    Passes = true,
                    Evidence = new() { "Found in: " + string.Join(", ", networkPolicies.Select(n => n.Name)) }
                });
            }
        }

        private void CheckSecretManagement()
        {
            var vaultRefs = _resources.Where(r => 
                r.Spec?.TryGetValue("secrets", out _) == true ||
                r.Metadata?.TryGetValue("annotations", out _) == true &&
                (string?)r.Metadata["annotations"]?["vault.hashicorp.com/agent-inject"] != null);

            if (vaultRefs.Any())
            {
                _findings.Add(new Finding
                {
                    ControlId = $"{HipaaControls.INTEGRITY_CONTROLS}:IA-5",
                    ResourcePath = string.Join(", ", vaultRefs.Select(r => r.Name)),
                    Description = "Secrets managed via HashiCorp Vault detected.",
                    Passes = true,
                    Evidence = new() { "Using Vault for secret injection" }
                });
            }

            var plainTextSecrets = _resources.Where(r => 
                r.Kind == "ConfigMap" &&
                (string?)r.Spec["data"]?["password"] != null ||
                (string?)r.Spec["data"]?["api-key"] != null);

            if (plainTextSecrets.Any())
            {
                _findings.Add(new Finding
                {
                    ControlId = $"{HipaaControls.ACCESS_CONTROL}:AC-2",
                    ResourcePath = string.Join(", ", plainTextSecrets.Select(c => c.Name)),
                    Description = "Potential secrets in ConfigMaps. Consider moving to Secrets.",
                    Passes = false,
                    Evidence = new() { "Check: " + string.Join(", ", plainTextSecrets.Select(c => c.Name)) }
                });
            }
        }

        public void GenerateScorecard()
        {
            var totalControls = _findings.DistinctBy(f => f.ControlId).Count();
            var passing = _findings.Where(f => f.Passes).DistinctBy(f => f.ControlId).Count();
            
            Console.WriteLine($"\n=== HIPAA Business Associate Readiness Scorecard ===");
            Console.WriteLine($"Total Controls Evaluated: {totalControls}");
            Console.WriteLine($"Passing: {passing} | Failing: {totalControls - passing}");
            Console.WriteLine($"Score: {(double)passing / totalControls * 100:F2}%\n");

            var byCategory = _findings.GroupBy(f => f.Category).ToDictionary(g => g.Key, g => g.ToList());
            
            foreach (var cat in byCategory.OrderBy(kvp => kvp.Key))
            {
                Console.WriteLine($"--- {cat.Key} ---");
                foreach (var finding in cat.Value)
                {
                    var status = finding.Passes ? "[PASS]" : "[FAIL]";
                    Console.WriteLine($"  {status} {finding.ControlId}: {finding.Description}");
                }
            }

            if (_findings.Any(f => !f.Passes))
            {
                Console.WriteLine("\n=== Priority Remediation Items ===");
                var failing = _findings.Where(f => !f.Passes).OrderByDescending(f => f.Category == HipaaControls.ACCESS_CONTROL);
                foreach (var item in failing.Take(5))
                {
                    Console.WriteLine($"  • {item.ControlId}: {item.Description}");
                }
            }
        }

        public static void Main(string[] args)
        {
            // Demo: Sample HIPAA manifest scan
            var scanner = new HipaaScanner();

            // Sample manifests (real-world would read from files/cluster)
            string[] samples = new[]
            {
                @"---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
spec:
  automountServiceAccountToken: true",
                
                @"---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    audit-log-enabled: ""true""
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        backend:
          service:
            name: api
            port:
              number: 80",

                @"---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database-url: ""postgres://user:pass@db/""
  api-key: ""sk-1234567890""",

                @"---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
subjects:
- kind: User
  name: john-doe
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io"
            };

            foreach (var sample in samples)
                scanner.AddManifest(sample);

            // Run the scan
            scanner.Scan();

            // Generate and display scorecard
            scanner.GenerateScorecard();

            // Output detailed JSON for CI/CD pipelines
            var output = JsonSerializer.Serialize(scanner._findings, new JsonSerializerOptions 
            { 
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            
            Console.WriteLine($"\n=== Raw JSON Output ===");
            Console.WriteLine(output);

            // Exit with appropriate code for CI/CD
            int exitCode = scanner._findings.Any(f => !f.Passes) ? 1 : 0;
            Environment.Exit(exitCode);
        }
    }
}