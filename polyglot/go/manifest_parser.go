package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// Data Models
// ============================================================================

type Manifest interface {
	Type() string
	Resources() []Resource
}

type Resource struct {
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Tags       map[string]string
	Metadata   map[string]interface{}
	Attributes map[string]interface{}
}

type HIPAAPolicy struct {
	Domain        string
	Category      string // Administrative, Physical, Technical, Organizational
	Rules         []Rule
	Weight        int
	Description    string
}

type Rule struct {
	Name           string
	Pattern        *regexp.Regexp
	CheckFunc      func(r Resource) bool
	Message        string
	Severity       Severity
	RequiredFields []string
}

type Severity string

const (
	SeverityInfo   Severity = "INFO"
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
	SeverityCritical = "CRITICAL"
)

type Finding struct {
	ResourceName  string
	Domain        string
	Category      string
	Rule          string
	Message       string
	Severity      Severity
	Remediation    string
}

type Scorecard struct {
	Timestamp         time.Time
	TotalResources     int
	PassCount          int
	FailCount          int
	WarnCount          int
	Domains            map[string]DomainResult
	OverallScore       float64
	RiskLevel          RiskLevel
}

type DomainResult struct {
	Name           string
	Category        string
	PassRate        float64
	FindingCount    int
	FailCount       int
	WarnCount       int
	Findings        []Finding
}

type RiskLevel string

const (
	RiskLow     RiskLevel = "LOW"
	RiskMedium  RiskLevel = "MEDIUM"
	RiskHigh    RiskLevel = "HIGH"
	RiskCritical = "CRITICAL"
)

// ============================================================================
// Parser Registry and Factory
// ============================================================================

type ParserRegistry struct {
	parsers map[string]Parser
}

func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: make(map[string]Parser),
	}
}

func (r *ParserRegistry) Register(name string, p Parser) {
	r.parsers[name] = p
}

func (r *ParserRegistry) Get(name string) Parser {
	if p, ok := r.parsers[name]; ok {
		return p
	}
	return nil
}

func (r *ParserRegistry) DetectAndParse(ctx context.Context, data []byte) (*Manifest, error) {
	for _, parser := range r.parsers {
		m, err := parser.Parse(ctx, data)
		if m != nil || err == nil {
			return m, err
		}
	}
	return nil, fmt.Errorf("no parser matched the manifest")
}

// ============================================================================
// Terraform Parser Implementation
// ============================================================================

type TerraformParser struct {
	regexpTerraformHeader *regexp.Regexp
}

func NewTerraformParser() *TerraformParser {
	p := &TerraformParser{}
	// Detect terraform files by header or extension
	p.regexpTerraformHeader = regexp.MustCompile(`(?i)terraform|\.tf$`)
	return p
}

func (p *TerraformParser) Parse(ctx context.Context, data []byte) (*Manifest, error) {
	content := string(data)
	
	// Check if this looks like terraform content
	if !p.regexpTerraformHeader.MatchString(content) && 
	   !strings.Contains(content, "resource ") &&
	   !strings.Contains(content, "\"type\"") {
		return nil, fmt.Errorf("does not appear to be Terraform manifest")
	}

	// Parse terraform resources
	resources := p.extractTerraformResources(content)
	
	if len(resources) == 0 {
		return &Manifest{Type: "terraform", Resources: []Resource{}}, nil
	}

	return &Manifest{
		Type:     "terraform",
		Resources: resources,
	}, nil
}

func (p *TerraformParser) extractTerraformResources(content string) []Resource {
	var resources []Resource
	
	lines := strings.Split(content, "\n")
	currentBlock := ""
	inResourceBlock := false
	resourceName := ""
	resourceType := ""
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if inResourceBlock && strings.HasPrefix(line, "}") {
			if resourceName != "" {
				resources = append(resources, Resource{
					Name:    resourceName,
					Type:    resourceType,
					Tags:    p.extractTags(currentBlock),
					Metadata: p.extractMetadata(currentBlock),
				})
			}
			inResourceBlock = false
			resourceName = ""
			resourceType = ""
			currentBlock = ""
		} else if inResourceBlock {
			currentBlock += line + "\n"
			
			if strings.HasPrefix(line, "resource ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					inResourceBlock = true
					resourceName = parts[2]
					// Extract type from resource block header
					typeParts := strings.Split(parts[1], ".")
					resourceType = typeParts[len(typeParts)-1]
				}
			} else if strings.HasPrefix(line, "tags = ") {
				tagsStr := strings.TrimPrefix(line, "tags = ")
				p.extractTagsFromStr(tagsStr)
			}
		} else if strings.Contains(line, "resource") && !inResourceBlock {
			inResourceBlock = true
			currentBlock = line + "\n"
		}
	}

	return resources
}

func (p *TerraformParser) extractTags(block string) map[string]string {
	tags := make(map[string]string)
	
	// Look for tags in various formats
	tagPatterns := []string{
		`tags\s*=\s*\{([^}]*)\}`,
		`"tags"\s*:\s*\{[^}]*\}`,
	}
	
	for _, pattern := range tagPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(block)
		if len(matches) > 1 {
			tagsStr := matches[1]
			
			// Parse individual tags
			tagRe := regexp.MustCompile(`"([^"]+)"\s*:\s*"([^"]*)"`|`([a-zA-Z0-9_-]+)\s*=\s*"([^"]*)"`)
			for _, m := range tagRe.FindAllStringSubmatch(tagsStr, -1) {
				if len(m) >= 3 {
					key := m[2]
					value := m[3]
					tags[strings.ToLower(key)] = value
				}
			}
		}
	}
	
	return tags
}

func (p *TerraformParser) extractMetadata(block string) map[string]interface{} {
	metadata := make(map[string]interface{})
	
	// Extract common metadata fields
	metaFields := []string{"name", "environment", "owner", "team", "project"}
	
	for _, field := range metaFields {
		pattern := fmt.Sprintf(`"%s"\s*:\s*"([^"]*)"`+`|`+fmt.Sprintf(`%s\s*=\s*"([^"]*)"`, field)
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(block)
		if len(matches) > 1 {
			value := matches[2]
			metadata[field] = value
		}
	}
	
	return metadata
}

// ============================================================================
// Kubernetes Parser Implementation
// ============================================================================

type K8sParser struct{}

func NewK8sParser() *K8sParser {
	return &K8sParser{}
}

func (p *K8sParser) Parse(ctx context.Context, data []byte) (*Manifest, error) {
	content := string(data)
	
	// Detect kubernetes manifests
	if !strings.Contains(content, "apiVersion:") || 
	   !strings.Contains(content, "kind:") {
		return nil, fmt.Errorf("does not appear to be Kubernetes manifest")
	}

	resources := p.extractK8sResources(content)
	
	if len(resources) == 0 {
		return &Manifest{Type: "kubernetes", Resources: []Resource{}}, nil
	}

	return &Manifest{
		Type:     "kubernetes",
		Resources: resources,
	}, nil
}

func (p *K8sParser) extractK8sResources(content string) []Resource {
	var resources []Resource
	
	lines := strings.Split(content, "\n")
	currentBlock := ""
	inBlock := false
	blockKind := ""
	blockName := ""
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if inBlock && strings.HasPrefix(line, "}") {
			if blockKind != "" {
				resources = append(resources, Resource{
					Name:    blockName,
					Type:    blockKind,
					Tags:    p.extractK8sTags(currentBlock),
					Metadata: p.extractK8sMetadata(currentBlock),
				})
			}
			inBlock = false
			blockKind = ""
			blockName = ""
			currentBlock = ""
		} else if inBlock {
			currentBlock += line + "\n"
			
			if strings.HasPrefix(line, "kind:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					inBlock = true
					blockKind = strings.TrimSpace(parts[1])
					blockName = ""
					
					// Extract name from metadata.name if present
					nameRe := regexp.MustCompile(`metadata:\s*\{[^}]*name:\s*"([^"]*)"`+`|`+
						`"name"\s*:\s*"([^"]*)"`+`|`+
						`name:\s*"([^"]*)"`)
					matches := nameRe.FindStringSubmatch(currentBlock)
					if len(matches) > 1 {
						blockName = matches[2]
					}
				}
			} else if strings.HasPrefix(line, "tags:") || strings.Contains(line, `"tags"`) {
				p.extractK8sTagsFromStr(currentBlock)
			}
		} else if strings.Contains(line, "kind:") && !inBlock {
			inBlock = true
			currentBlock = line + "\n"
		}
	}

	return resources
}

func (p *K8sParser) extractK8sTags(block string) map[string]string {
	tags := make(map[string]string)
	
	tagRe := regexp.MustCompile(`tags:\s*\{([^}]*)\}`+`|`+
		`"tags"\s*:\s*\{[^}]*\}`+`|`+
		`labels:\s*\{[^}]*\}`)
	
	matches := tagRe.FindStringSubmatch(block)
	if len(matches) > 1 {
		tagsStr := matches[1]
		
		tagRe := regexp.MustCompile(`"([^"]+)"\s*=\s*"([^"]*)"`+`|`+
			`([a-zA-Z0-9_-]+)\s*=\s*"([^"]*)"`)
		for _, m := range tagRe.FindAllStringSubmatch(tagsStr, -1) {
			if len(m) >= 3 {
				key := strings.ToLower(m[2])
				value := m[3]
				tags[key] = value
			}
		}
	}
	
	return tags
}

func (p *K8sParser) extractK8sMetadata(block string) map[string]interface{} {
	metadata := make(map[string]interface{})
	
	metaFields := []string{"namespace", "environment", "owner", "team"}
	
	for _, field := range metaFields {
		pattern := fmt.Sprintf(`"%s"\s*:\s*"([^"]*)"`+`|`+fmt.Sprintf(`%s\s*=\s*"([^"]*)"`, field)
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(block)
		if len(matches) > 1 {
			value := matches[2]
			metadata[field] = value
		}
	}
	
	return metadata
}

// ============================================================================
// CloudFormation Parser Implementation
// ============================================================================

type CFNParser struct{}

func NewCFNParser() *K8sParser {
	return &CFNParser{}
}

func (p *CFNParser) Parse(ctx context.Context, data []byte) (*Manifest, error) {
	content := string(data)
	
	if !strings.Contains(content, "AWSTemplateFormatVersion") && 
	   !strings.Contains(content, "Resources:") {
		return nil, fmt.Errorf("does not appear to be CloudFormation manifest")
	}

	resources := p.extractCFNResources(content)
	
	if len(resources) == 0 {
		return &Manifest{Type: "cloudformation", Resources: []Resource{}}, nil
	}

	return &Manifest{
		Type:     "cloudformation",
		Resources: resources,
	}, nil
}

func (p *CFNParser) extractCFNResources(content string) []Resource {
	var resources []Resource
	
	lines := strings.Split(content, "\n")
	currentBlock := ""
	inBlock := false
	blockType := ""
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if inBlock && strings.HasPrefix(line, "},") {
			if blockType != "" {
				resources = append(resources, Resource{
					Name:    p.extractCFNName(currentBlock),
					Type:    blockType,
					Tags:    p.extractCFNTags(currentBlock),
					Metadata: p.extractCFNMetadata(currentBlock),
				})
			}
			inBlock = false
			blockType = ""
			currentBlock = ""
		} else if inBlock {
			currentBlock += line + "\n"
			
			if strings.HasPrefix(line, "Resources:") || 
			   (inBlock && strings.Contains(line, "ResourceName") && !strings.Contains(currentBlock, "}")) {
				inBlock = true
				blockType = ""
				
				// Extract resource type
				typeRe := regexp.MustCompile(`"([A-Za-z0-9.]+)"\s*:\s*\{`)
				matches := typeRe.FindStringSubmatch(currentBlock)
				if len(matches) > 1 {
					blockType = matches[1]
				}
			} else if strings.Contains(line, "Tags:") || 
			   (inBlock && strings.Contains(line, `"Tags"`) && !strings.Contains(currentBlock, "}")) {
				p.extractCFNTagsFromStr(currentBlock)
			}
		} else if strings.Contains(line, "Resources:") && !inBlock {
			inBlock = true
			currentBlock = line + "\n"
		}
	}

	return resources
}

func (p *CFNParser) extractCFNName(block string) string {
	nameRe := regexp.MustCompile(`ResourceName\s*:\s*"([^"]*)"`+`|`+
		`"LogicalResourceId"\s*=\s*"([^"]*)"`)
	
	matches := nameRe.FindStringSubmatch(block)
	if len(matches) > 1 {
		return matches[2]
	}
	return ""
}

func (p *CFNParser) extractCFNTags(block string) map[string]string {
	tags := make(map[string]string)
	
	tagRe := regexp.MustCompile(`Tags\s*:\s*\{([^}]*)\}`+`|`+
		`"Tags"\s*:\s*\{[^}]*\}`)
	
	matches := tagRe.FindStringSub