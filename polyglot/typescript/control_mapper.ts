import { ControlDefinition, ScanResult, MappedResult, Scorecard, ComplianceLevel } from './types';

export interface ControlMapperConfig {
  addressableThreshold: number; // Default 0.8 for "addressable" controls
  recommendedThreshold: number; // Default 1.0 for "recommended" controls
  partialCreditEnabled: boolean; // Allow <100% compliance to score
}

export const DEFAULT_CONFIG: ControlMapperConfig = {
  addressableThreshold: 0.8,
  recommendedThreshold: 1.0,
  partialCreditEnabled: true,
};

/**
 * Maps a raw scan finding against a control definition.
 * Returns the mapped result with compliance level and evidence.
 */
export function mapControl(
  finding: ScanResult,
  controlDef: ControlDefinition,
  config?: Partial<ControlMapperConfig>
): MappedResult {
  const effectiveConfig = { ...DEFAULT_CONFIG, ...config };

  // Calculate compliance percentage (0-1)
  let complianceScore: number;
  
  if (controlDef.type === 'addressable') {
    complianceScore = Math.min(1.0, finding.compliancePercentage);
  } else if (controlDef.type === 'recommended') {
    complianceScore = Math.min(1.0, finding.compliancePercentage * effectiveConfig.recommendedThreshold);
  } else {
    complianceScore = finding.compliancePercentage;
  }

  // Determine compliance level
  let level: ComplianceLevel;
  if (complianceScore >= 1.0) {
    level = 'COMPLIANT';
  } else if (complianceScore >= effectiveConfig.addressableThreshold) {
    level = 'PARTIAL';
  } else {
    level = 'NON_COMPLIANT';
  }

  // Build evidence chain
  const evidence: string[] = [];
  
  if (finding.evidence?.length) {
    evidence.push(...finding.evidence);
  }
  
  if (controlDef.overrideReason) {
    evidence.push(`Override reason: ${controlDef.overrideReason}`);
  }

  // Check for partial credit eligibility
  let hasPartialCredit = false;
  if (effectiveConfig.partialCreditEnabled && complianceScore < 1.0 && level !== 'NON_COMPLIANT') {
    const partialEvidence = controlDef.partialCreditRules?.map(rule => 
      rule.test(finding) ? `Partial credit: ${rule.reason}` : null
    ).filter(Boolean);
    
    if (partialEvidence.length > 0) {
      evidence.push(...partialEvidence);
      hasPartialCredit = true;
    }
  }

  return {
    controlId: controlDef.id,
    controlName: controlDef.name,
    category: controlDef.category,
    complianceLevel: level,
    complianceScore: complianceScore,
    evidence,
    partialCredit: hasPartialCredit,
    mappedToRules: controlDef.hipaaRules.map(r => r.code).filter(Boolean),
  };
}

/**
 * Aggregates multiple mapped results into a scorecard.
 */
export function aggregateScorecard(
  mappedResults: MappedResult[],
  config?: Partial<ControlMapperConfig>
): Scorecard {
  const effectiveConfig = { ...DEFAULT_CONFIG, ...config };

  // Group by category
  const byCategory: Record<string, MappedResult[]> = {};
  
  for (const result of mappedResults) {
    if (!byCategory[result.category]) {
      byCategory[result.category] = [];
    }
    byCategory[result.category].push(result);
  }

  // Calculate category scores
  const categories: Record<string, { total: number; compliant: number; partial: number }> = {};
  
  for (const [category, results] of Object.entries(byCategory)) {
    let totalScore = 0;
    let compliantCount = 0;
    let partialCount = 0;

    for (const result of results) {
      if (result.complianceLevel === 'COMPLIANT') {
        compliantCount++;
      } else if (result.complianceLevel === 'PARTIAL' && effectiveConfig.partialCreditEnabled) {
        totalScore += result.complianceScore;
        partialCount++;
      }
    }

    const categoryTotal = results.length;
    categories[category] = {
      total: compliantCount + partialCount,
      compliant: compliantCount,
      partial: partialCount,
      averageScore: totalScore / (compliantCount + partialCount) || 0,
    };
  }

  // Calculate overall score
  let grandTotal = 0;
  let grandCompliant = 0;
  let grandPartial = 0;
  let weightedSum = 0;
  let totalWeight = 0;

  for (const [category, stats] of Object.entries(categories)) {
    const weight = stats.total / mappedResults.length;
    weightedSum += stats.averageScore * weight;
    totalWeight += weight;
    
    grandTotal += stats.total;
    grandCompliant += stats.compliant;
    grandPartial += stats.partial;
  }

  const overallScore = totalWeight > 0 ? weightedSum / totalWeight : 0;
  
  // Determine readiness status
  let readinessStatus: 'READY' | 'NEEDS_REVIEW' | 'CRITICAL';
  if (overallScore >= 1.0) {
    readinessStatus = 'READY';
  } else if (overallScore >= 0.85) {
    readinessStatus = 'NEEDS_REVIEW';
  } else {
    readinessStatus = 'CRITICAL';
  }

  // Build gaps report
  const gaps: { category: string; controlId: string; currentLevel: ComplianceLevel; requiredLevel: ComplianceLevel }[] = [];
  
  for (const result of mappedResults) {
    if (result.complianceLevel !== 'COMPLIANT') {
      gaps.push({
        category: result.category,
        controlId: result.controlId,
        currentLevel: result.complianceLevel,
        requiredLevel: 'COMPLIANT',
      });
    }
  }

  // Sort gaps by severity (non-compliant first)
  const severityOrder = { NON_COMPLIANT: 0, PARTIAL: 1 };
  gaps.sort((a, b) => 
    (severityOrder[a.currentLevel] || 2) - (severityOrder[b.currentLevel] || 2)
  );

  return {
    overallScore: Math.round(overallScore * 100) / 100,
    readinessStatus,
    totalControls: mappedResults.length,
    compliantCount: grandCompliant,
    partialCount: grandPartial,
    byCategory,
    gaps,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Generates a human-readable report from a scorecard.
 */
export function generateReport(scorecard: Scorecard): string {
  const lines: string[] = [];

  // Header
  lines.push('='.repeat(60));
  lines.push(`HIPAA SECURITY RULE READINESS SCORECARD`);
  lines.push(`Generated: ${scorecard.timestamp}`);
  lines.push('='.repeat(60));
  lines.push('');

  // Overall Summary
  const statusEmoji = scorecard.readinessStatus === 'READY' ? '✅' : 
                     scorecard.readinessStatus === 'NEEDS_REVIEW' ? '⚠️' : '🔴';
  
  lines.push(`OVERALL STATUS: ${statusEmoji} ${scorecard.readinessStatus}`);
  lines.push(`Overall Score: ${scorecard.overallScore.toFixed(2)} / 1.00`);
  lines.push(`Controls Analyzed: ${scorecard.totalControls}`);
  lines.push(`Compliant: ${scorecard.compliantCount} | Partial: ${scorecard.partialCount}`);
  lines.push('');

  // Category Breakdown
  lines.push('-'.repeat(60));
  lines.push('CATEGORY BREAKDOWN');
  lines.push('-'.repeat(60));
  
  const sortedCategories = Object.entries(scorecard.byCategory)
    .sort((a, b) => (b[1].total - a[1].total));

  for (const [category, stats] of sortedCategories) {
    const barWidth = Math.min(40, Math.round(stats.averageScore * 40));
    const bar = '█'.repeat(barWidth) + '░'.repeat(40 - barWidth);
    
    lines.push(`\n${category}:`);
    lines.push(`  Score: ${stats.averageScore.toFixed(2)} | Status: ${stats.total > 0 ? (stats.compliant === stats.total ? 'COMPLIANT' : 'MIXED') : 'NO DATA'}`);
    lines.push(`  Progress: [${bar}] ${(stats.averageScore * 100).toFixed(0)}%`);
  }

  // Gaps Report
  if (scorecard.gaps.length > 0) {
    lines.push('');
    lines.push('-'.repeat(60));
    lines.push(`GAPS IDENTIFIED: ${scorecard.gaps.length}`);
    lines.push('-'.repeat(60));

    for (const gap of scorecard.gaps) {
      const severity = gap.currentLevel === 'NON_COMPLIANT' ? 'HIGH' : 
                      gap.currentLevel === 'PARTIAL' ? 'MEDIUM' : 'LOW';
      
      lines.push(`\n  [${severity}] ${gap.controlId}`);
      lines.push(`    Category: ${gap.category}`);
      lines.push(`    Current: ${gap.currentLevel} | Required: COMPLIANT`);
    }

    lines.push('');
  } else {
    lines.push('');
    lines.push('-'.repeat(60));
    lines.push('GAPS IDENTIFIED: 0 (All controls compliant)');
    lines.push('-'.repeat(60));
  }

  // Recommendations for non-ready status
  if (scorecard.readinessStatus !== 'READY') {
    lines.push('');
    lines.push('-'.repeat(60));
    lines.push('RECOMMENDATIONS');
    lines.push('-'.repeat(60));
    
    const criticalGaps = scorecard.gaps.filter(g => g.currentLevel === 'NON_COMPLIANT');
    
    if (criticalGaps.length > 0) {
      lines.push('\nCRITICAL: Address the following immediately:');
      for (const gap of criticalGaps.slice(0, 5)) {
        lines.push(`  • ${gap.controlId} (${gap.category})`);
      }
    }

    if (scorecard.partialCount > 0) {
      lines.push('\nPARTIAL: Consider strengthening these areas:');
      const partialGaps = scorecard.gaps.filter(g => g.currentLevel === 'PARTIAL').slice(0, 5);
      for (const gap of partialGaps) {
        lines.push(`  • ${gap.controlId} (${gap.category})`);
      }
    }

    if (criticalGaps.length === 0 && scorecard.partialCount === 0) {
      lines.push('\nMinor improvements needed to achieve full readiness.');
    }
  }

  return lines.join('\n');
}

/**
 * Main entry point for running the control mapper.
 */
export async function runControlMapper(
  scanResults: ScanResult[],
  controls: ControlDefinition[] = [],
  config?: Partial<ControlMapperConfig>
): Promise<string> {
  // Map all findings against their respective controls
  const mappedResults: MappedResult[] = [];

  for (const result of scanResults) {
    const matchingControl = controls.find(c => c.id === result.controlId);
    
    if (!matchingControl) {
      // Unknown control - treat as generic addressable
      mappedResults.push({
        controlId: result.controlId,
        controlName: `Unknown Control (${result.controlId})`,
        category: 'Other',
        complianceLevel: result.compliancePercentage >= 0.8 ? 'COMPLIANT' : 
                       result.compliancePercentage >= 0.5 ? 'PARTIAL' : 'NON_COMPLIANT',
        complianceScore: result.compliancePercentage,
        evidence: result.evidence || [],
        partialCredit: false,
        mappedToRules: [],
      });
    } else {
      const mapped = mapControl(result, matchingControl, config);
      mappedResults.push(mapped);
    }
  }

  // Aggregate into scorecard
  const scorecard = aggregateScorecard(mappedResults, config);

  // Generate report
  const report = generateReport(scorecard);

  return report;
}

// ============================================
// DEMO / RUNNABLE ENTRY POINT
// ============================================

if (import.meta.url === `file://${process.argv[1]}`) {
  // Sample scan results
  const sampleResults: ScanResult[] = [
    {
      controlId: 'IAM-001',
      controlName: 'IAM Least Privilege Policy',
      compliancePercentage: 0.95,
      evidence: ['Policy document reviewed on 2024-01-15', '87% of users follow least privilege'],
    },
    {
      controlId: 'ENCR-003',
      controlName: 'Encryption at Rest',
      compliancePercentage: 0.6,
      evidence: ['RDS encrypted (yes)', 'S3 bucket A unencrypted', 'Lambda layers not encrypted'],
    },
    {
      controlId: 'AUDT-005',
      controlName: 'Audit Logging',
      compliancePercentage: 1.0,
      evidence: ['CloudTrail enabled globally', 'Logs retained for 90 days'],
    },
    {
      controlId: 'TRNS-002',
      controlName: 'TLS in Transit',
      compliancePercentage: 0.85,
      evidence: ['API Gateway uses TLS 1.2+', 'Some internal services use HTTP'],
    },
    {
      controlId: 'ACCE-007',
      controlName: 'Access Control Procedures',
      compliancePercentage: 0.4,
      evidence: ['No documented procedures found', 'Ad-hoc access granted frequently'],
    },
  ];

  // Sample control definitions with HIPAA mappings
  const sampleControls: ControlDefinition[] = [
    {
      id: 'IAM-001',
      name: 'IAM Least Privilege Policy',
      category: 'Access Control',
      type: 'addressable',
      hipaaRules: [{ code: 'AC.2.a', description: 'Standardized procedures' }],
    },
    {
      id: 'ENCR-003',
      name: 'Encryption at Rest',
      category: 'Transmission Security',
      type: 'addressable',
      hipaaRules: [{ code: 'TS.1.a', description: 'Transmission security' }],
    },
    {
      id: 'AUDT-005',
      name: 'Audit Logging',
      category: 'Audit Controls',
      type: 'addressable',
      hipaaRules: [{ code: 'AU.1.a', description: 'Standardized procedures' }],
    },
    {
      id: 'TRNS-002',
      name: 'TLS in Transit',
      category: 'Transmission Security',
      type: 'addressable',
      hipaaRules: [{ code: 'TS.1.b', description: 'Encryption' }],
    },
    {
      id: 'ACCE-007',
      name: 'Access Control Procedures',
      category: 'Access Control',
      type: 'addressable',
      hipaaRules: [{ code: 'AC.2.a', description: 'Standardized procedures' }],
    },
  ];

  // Run the mapper
  const report = runControlMapper(sampleResults, sampleControls);

  console.log(report);
}