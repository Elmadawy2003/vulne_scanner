package scanning

import (
    "encoding/json"
    "fmt"
    "sync"
    "time"
)

// VulnerabilityType نوع الثغرة
type VulnerabilityType string

// تعريف أنواع الثغرات
const (
    // ثغرات الحقن
    SQLInjection          VulnerabilityType = "sql_injection"
    NoSQLInjection       VulnerabilityType = "nosql_injection"
    CommandInjection     VulnerabilityType = "command_injection"
    LDAPInjection        VulnerabilityType = "ldap_injection"
    XMLInjection         VulnerabilityType = "xml_injection"
    
    // ثغرات التطبيقات
    XSS                  VulnerabilityType = "xss"
    CSRF                 VulnerabilityType = "csrf"
    SSRF                 VulnerabilityType = "ssrf"
    XXE                  VulnerabilityType = "xxe"
    
    // ثغرات التكوين
    SecurityMisconfig    VulnerabilityType = "security_misconfig"
    WeakCrypto          VulnerabilityType = "weak_crypto"
    InsecureHeaders     VulnerabilityType = "insecure_headers"
    
    // ثغرات المصادقة والتفويض
    BrokenAuth          VulnerabilityType = "broken_auth"
    BrokenAccessControl VulnerabilityType = "broken_access"
    
    // ثغرات متقدمة
    BusinessLogic       VulnerabilityType = "business_logic"
    APIVulnerabilities  VulnerabilityType = "api_vulnerabilities"
    WebSocketVulns      VulnerabilityType = "websocket_vulnerabilities"
)

// Vulnerability تمثل ثغرة أمنية مكتشفة
type Vulnerability struct {
    ID            string            `json:"id"`
    Type          VulnerabilityType `json:"type"`
    Name          string            `json:"name"`
    Description   string            `json:"description"`
    Severity      string            `json:"severity"`
    CVSS          float64           `json:"cvss"`
    CVE           string            `json:"cve,omitempty"`
    CWE           string            `json:"cwe,omitempty"`
    
    Target        string            `json:"target"`
    URL           string            `json:"url"`
    Path          string            `json:"path,omitempty"`
    Parameter     string            `json:"parameter,omitempty"`
    
    Found         time.Time         `json:"found"`
    Proof         string            `json:"proof,omitempty"`
    Solution      string            `json:"solution,omitempty"`
    References    []string          `json:"references,omitempty"`
    
    ExtraData     map[string]interface{} `json:"extra_data,omitempty"`
    Tags          []string          `json:"tags,omitempty"`
}

// VulnerabilityBuilder مساعد لبناء كائنات الثغرات
type VulnerabilityBuilder struct {
    vuln Vulnerability
}

// NewVulnerabilityBuilder ينشئ مساعد جديد لبناء الثغرات
func NewVulnerabilityBuilder() *VulnerabilityBuilder {
    return &VulnerabilityBuilder{
        vuln: Vulnerability{
            Found: time.Now(),
            ExtraData: make(map[string]interface{}),
        },
    }
}

// WithType تحديد نوع الثغرة
func (vb *VulnerabilityBuilder) WithType(t VulnerabilityType) *VulnerabilityBuilder {
    vb.vuln.Type = t
    return vb
}

// WithName تحديد اسم الثغرة
func (vb *VulnerabilityBuilder) WithName(name string) *VulnerabilityBuilder {
    vb.vuln.Name = name
    return vb
}

// WithSeverity تحديد خطورة الثغرة
func (vb *VulnerabilityBuilder) WithSeverity(severity string) *VulnerabilityBuilder {
    vb.vuln.Severity = severity
    return vb
}

// WithCVSS تحديد درجة CVSS
func (vb *VulnerabilityBuilder) WithCVSS(cvss float64) *VulnerabilityBuilder {
    vb.vuln.CVSS = cvss
    return vb
}

// Build بناء كائن الثغرة
func (vb *VulnerabilityBuilder) Build() Vulnerability {
    return vb.vuln
}

// VulnerabilityManager مدير الثغرات
type VulnerabilityManager struct {
    vulnerabilities []Vulnerability
    mu             sync.RWMutex
}

// NewVulnerabilityManager ينشئ مدير جديد للثغرات
func NewVulnerabilityManager() *VulnerabilityManager {
    return &VulnerabilityManager{
        vulnerabilities: make([]Vulnerability, 0),
    }
}

// AddVulnerability إضافة ثغرة جديدة
func (vm *VulnerabilityManager) AddVulnerability(vuln Vulnerability) {
    vm.mu.Lock()
    defer vm.mu.Unlock()
    vm.vulnerabilities = append(vm.vulnerabilities, vuln)
}

// GetVulnerabilities استرجاع جميع الثغرات
func (vm *VulnerabilityManager) GetVulnerabilities() []Vulnerability {
    vm.mu.RLock()
    defer vm.mu.RUnlock()
    return vm.vulnerabilities
}

// GetBySeverity استرجاع الثغرات حسب مستوى الخطورة
func (vm *VulnerabilityManager) GetBySeverity(severity string) []Vulnerability {
    vm.mu.RLock()
    defer vm.mu.RUnlock()
    
    var result []Vulnerability
    for _, vuln := range vm.vulnerabilities {
        if vuln.Severity == severity {
            result = append(result, vuln)
        }
    }
    return result
}

// GetByType استرجاع الثغرات حسب النوع
func (vm *VulnerabilityManager) GetByType(vulnType VulnerabilityType) []Vulnerability {
    vm.mu.RLock()
    defer vm.mu.RUnlock()
    
    var result []Vulnerability
    for _, vuln := range vm.vulnerabilities {
        if vuln.Type == vulnType {
            result = append(result, vuln)
        }
    }
    return result
}

// ExportToJSON تصدير الثغرات إلى JSON
func (vm *VulnerabilityManager) ExportToJSON() ([]byte, error) {
    vm.mu.RLock()
    defer vm.mu.RUnlock()
    
    return json.MarshalIndent(vm.vulnerabilities, "", "    ")
}

// GetStatistics إحصائيات الثغرات
func (vm *VulnerabilityManager) GetStatistics() map[string]int {
    vm.mu.RLock()
    defer vm.mu.RUnlock()
    
    stats := make(map[string]int)
    for _, vuln := range vm.vulnerabilities {
        stats[vuln.Severity]++
        stats[string(vuln.Type)]++
    }
    return stats
} 