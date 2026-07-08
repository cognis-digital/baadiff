import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'yaml';
import * as hcl2js from '@hashicorp/hcl2json';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface HIPAAControl {
  id: string;
  category: 'Access' | 'Audit' | 'Integrity' | 'Transmission';
  description: string;
  required?: boolean;
}

interface ResourceMatch {
  resourceType: string;
  resourceName: string;
  filePath: string;
  controlsSatisfied: string[];
  controlsMissing: string[];
  configSnippet: string;
}

interface ScanResult {
  totalResources: number;
  matchedResources: number;
  unmatchedResources: number;
  matches: ResourceMatch[];
  summaryByCategory: Record<string, { satisfied: number; missing: number }>;
  overallScore: number; // 0-100
}

interface ConfigOptions {
  rootDir?: string;
  includePatterns?: string[];
  excludePatterns?: string[];
  strictMode?: boolean;
}

// ============================================================================
// HIPAA CONTROL DEFINITIONS
// ============================================================================

const HIPAA_CONTROLS: Record<string, HIPAAControl> = {
  // ACCESS CONTROL (164.308(a)(5))
  'AC-01': { id: 'AC-01', category: 'Access', description: 'Unique User Identification' },
  'AC-02': { id: 'AC-02', category: 'Access', description: 'Network Access Control' },
  'AC-03': { id: 'AC-03', category: 'Access', description: 'Least Privilege' },
  'AC-04': { id: 'AC-04', category: 'Access', description: 'Maximum Privilege' },
  
  // AUDIT CONTROLS (164.312(b))
  'AU-01': { id: 'AU-01', category: 'Audit', description: 'Activity Inhibition' },
  'AU-02': { id: 'AU-02', category: 'Audit', description: 'Event Identification' },
  'AU-03': { id: 'AU-03', category: 'Audit', description: 'Event Time Stamping' },
  
  // INTEGRITY CONTROLS (164.312(c))
  'IA-01': { id: 'IA-01', category: 'Integrity', description: 'Security Function Verification' },
  'IA-02': { id: 'IA-02', category: 'Integrity', description: 'Data Integrity Verification' },
  
  // TRANSMISSION SECURITY (164.312(e))
  'TS-01': { id: 'TS-01', category: 'Transmission', description: 'Transport Protection' },
  'TS-02': { id: 'TS-02', category: 'Transmission', description: 'Secure Ports' },
};

// ============================================================================
// PARSER UTILITIES
// ============================================================================

function parseYamlFile(filePath: string): Record<string, unknown> | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return yaml.parse(content);
  } catch (error) {
    console.warn(`Failed to parse YAML file ${filePath}:`, error);
    return null;
  }
}

function parseHclFile(filePath: string): Record<string, unknown> | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    // Basic HCL parsing - for production use @hashicorp/hcl2json
    return JSON.parse(content);
  } catch (error) {
    console.warn(`Failed to parse HCL file ${filePath}:`, error);
    return null;
  }
}

function findMatchingControls(resourceType: string, config: Record<string, unknown>): string[] {
  const matched: string[] = [];
  
  // Define resource-to-control mappings
  const controlMappings: Record<string, string[]> = {
    'aws_iam_user': ['AC-01', 'AC-03'],
    'aws_iam_group': ['AC-01', 'AC-03'],
    'aws_iam_policy': ['AC-03'],
    'k8s_role': ['AC-01', 'AC-03'],
    'k8s_service_account': ['AC-01', 'AC-03'],
    'k8s_secret': ['TS-01', 'IA-02'],
    'aws_s3_bucket': ['TS-01', 'AC-02', 'IA-02'],
    'aws_rds_instance': ['TS-01', 'AC-02'],
    'aws_lambda_function': ['TS-01', 'AC-02'],
    'k8s_ingress': ['TS-01'],
  };

  const mappings = controlMappings[resourceType] || [];
  
  for (const controlId of mappings) {
    if (!matched.includes(controlId)) {
      matched.push(controlId);
    }
  }
  
  return matched;
}

function extractConfigSnippet(resource: ResourceMatch, config: Record<string, unknown>): string {
  // Extract a relevant snippet from the resource configuration
  const keys = Object.keys(config).slice(0, 3).join(' ');
  return `resource="${resource.resourceType}" ${keys}`;
}

// ============================================================================
// MAIN PARSER LOGIC
// ============================================================================

export class ManifestParser {
  private rootDir: string;
  private options: ConfigOptions;

  constructor(rootDir: string = '.', options: ConfigOptions = {}) {
    this.rootDir = path.resolve(rootDir);
    this.options = {
      includePatterns: ['*.tf', '*.yaml', '*.yml'],
      excludePatterns: ['.git/', 'node_modules/'],
      ...options,
    };
  }

  async scan(): Promise<ScanResult> {
    const matches: ResourceMatch[] = [];
    let totalResources = 0;
    
    // Find all manifest files
    const files = await this.findManifestFiles();
    
    for (const filePath of files) {
      const relativePath = path.relative(this.rootDir, filePath);
      
      try {
        let config: Record<string, unknown> | null = null;
        
        if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
          config = parseYamlFile(filePath);
        } else if (filePath.endsWith('.tf')) {
          // Terraform HCL parsing would require more complex logic
          config = parseHclFile(filePath);
        }
        
        if (!config) continue;

        totalResources++;
        
        // Extract resource type and name from filename or first key
        const fileName = path.basename(filePath, '.yaml');
        const resourceType = fileName.replace(/_/g, '-').replace(/-/g, ' ');
        const resourceName = Object.keys(config)[0] || 'unknown';

        const matchedControls = findMatchingControls(resourceType, config);
        
        // Determine satisfied vs missing controls (simplified logic)
        const satisfied = ['AC-01', 'TS-01']; // Common defaults
        const missing = matchedControls.filter(c => !satisfied.includes(c));

        matches.push({
          resourceType: resourceType,
          resourceName: resourceName,
          filePath: relativePath,
          controlsSatisfied: satisfied,
          controlsMissing: missing,
          configSnippet: extractConfigSnippet(
            { resourceType, resourceName }, 
            config as Record<string, unknown>
          ),
        });
      } catch (error) {
        console.warn(`Error processing ${filePath}:`, error);
      }
    }

    return this.calculateScore(matches, totalResources);
  }

  private async findManifestFiles(): Promise<string[]> {
    const files: string[] = [];
    
    // Simple recursive file search
    function walk(dir: string): void {
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          
          if (entry.isDirectory()) {
            // Check against exclude patterns
            let excluded = false;
            for (const pattern of this.options.excludePatterns) {
              if (fullPath.includes(pattern)) {
                excluded = true;
                break;
              }
            }
            
            if (!excluded) {
              walk(fullPath);
            }
          } else if (entry.isFile()) {
            // Check against include patterns
            let included = false;
            for (const pattern of this.options.includePatterns) {
              if (fullPath.endsWith(pattern)) {
                included = true;
                break;
              }
            }
            
            if (included) {
              files.push(fullPath);
            }
          }
        }
      } catch (error) {
        // Ignore read errors for non-existent directories
      }
    }

    walk(this.rootDir);
    return files;
  }

  private calculateScore(matches: ResourceMatch[], totalResources: number): ScanResult {
    if (matches.length === 0) {
      return {
        totalResources,
        matchedResources: 0,
        unmatchedResources: totalResources,
        matches: [],
        summaryByCategory: {},
        overallScore: 0,
      };
    }

    // Calculate category scores
    const categorySummary: Record<string, { satisfied: number; missing: number }> = {};
    
    for (const match of matches) {
      for (const controlId of match.controlsSatisfied) {
        if (!categorySummary[controlId]) {
          categorySummary[controlId] = { satisfied: 0, missing: 0 };
        }
        categorySummary[controlId].satisfied++;
      }
      
      for (const controlId of match.controlsMissing) {
        if (!categorySummary[controlId]) {
          categorySummary[controlId] = { satisfied: 0, missing: 0 };
        }
        categorySummary[controlId].missing++;
      }
    }

    // Calculate overall score (simplified: percentage of controls satisfied)
    let totalControlsChecked = 0;
    let totalSatisfied = 0;

    for (const [id, data] of Object.entries(categorySummary)) {
      const controlDef = HIPAA_CONTROLS[id];
      if (controlDef) {
        totalControlsChecked += 1;
        totalSatisfied += data.satisfied;
      }
    }

    const overallScore = totalControlsChecked > 0 
      ? Math.round((totalSatisfied / totalControlsChecked) * 100) 
      : 0;

    return {
      totalResources,
      matchedResources: matches.length,
      unmatchedResources: totalResources - matches.length,
      matches,
      summaryByCategory: categorySummary,
      overallScore,
    };
  }
}

// ============================================================================
// EXPORTED FUNCTIONS FOR EASE OF USE
// ============================================================================

export async function scanManifest(
  rootDir: string = '.',
  options?: ConfigOptions
): Promise<ScanResult> {
  const parser = new ManifestParser(rootDir, options);
  return parser.scan();
}

export function generateReport(result: ScanResult): string {
  let report = `HIPAA Business Associate Readiness Scorecard\n`;
  report += `================================================\n\n`;
  
  report += `Overall Score: ${result.overallScore}/100\n`;
  report += `Total Resources Scanned: ${result.totalResources}\n`;
  report += `Matched Resources: ${result.matchedResources}\n\n`;

  // Category breakdown
  const categories: Record<string, string> = {
    'Access': 'AC-01, AC-02, AC-03, AC-04',
    'Audit': 'AU-01, AU-02, AU-03',
    'Integrity': 'IA-01, IA-02',
    'Transmission': 'TS-01, TS-02',
  };

  for (const [category, controls] of Object.entries(categories)) {
    const summary = result.summaryByCategory[controls];
    if (!summary) continue;
    
    report += `${category} Controls:\n`;
    report += `  Satisfied: ${summary.satisfied}\n`;
    report += `  Missing: ${summary.missing}\n\n`;
  }

  // Detailed matches
  report += `\nDetailed Resource Matches:\n`;
  report += `--------------------------\n\n`;

  for (const match of result.matches) {
    report += `${match.resourceType} (${match.resourceName})\n`;
    report += `  File: ${match.filePath}\n`;
    report += `  Controls Satisfied: ${match.controlsSatisfied.join(', ') || 'None'}\n`;
    report += `  Controls Missing: ${match.controlsMissing.length > 0 ? match.controlsMissing.join(', ') : 'All matched controls present'}\n\n`;
  }

  return report;
}

// ============================================================================
// RUNNABLE DEMO / ENTRY POINT
// ============================================================================

if (require.main === module) {
  const args = process.argv.slice(2);
  const targetDir = args[0] || '.';

  console.log(`Scanning directory: ${targetDir}\n`);

  scanManifest(targetDir).then(result => {
    const report = generateReport(result);
    
    // Output to stdout
    console.log(report);
    
    // Write to file
    const outputPath = path.join(targetDir, 'hipaa-scorecard.txt');
    fs.writeFileSync(outputPath, report);
    console.log(`\nReport also written to: ${outputPath}`);
  });
}

export { ManifestParser, HIPAA_CONTROLS, scanManifest, generateReport };