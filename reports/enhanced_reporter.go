package reports

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"vulne_scanner/config"
	"vulne_scanner/logs"
)

// EnhancedReporter المنشئ المحسن للتقارير
type EnhancedReporter struct {
	config     *config.Config
	templates  map[string]*template.Template
	outputDir  string
}

// ReportFormat صيغة التقرير
type ReportFormat string

const (
	JSON  ReportFormat = "json"
	HTML  ReportFormat = "html"
	PDF   ReportFormat = "pdf"
	XML   ReportFormat = "xml"
	EXCEL ReportFormat = "excel"
)

// EnhancedReport التقرير المحسن
type EnhancedReport struct {
	// معلومات عامة
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Duration    string    `json:"duration"`

	// إحصائيات
	Statistics ReportStatistics `json:"statistics"`

	// نتائج الفحص
	Vulnerabilities []VulnerabilityDetails `json:"vulnerabilities"`
	ScannerResults  map[string]ScannerResult `json:"scanner_results"`

	// معلومات إضافية
	Environment EnvironmentInfo `json:"environment"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ReportStatistics إحصائيات التقرير
type ReportStatistics struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	SeverityCounts      map[string]int `json:"severity_counts"`
	TypeCounts          map[string]int `json:"type_counts"`
	ScannerCounts       map[string]int `json:"scanner_counts"`
	SuccessRate        float64 `json:"success_rate"`
	AverageTime        string  `json:"average_time"`
}

// VulnerabilityDetails تفاصيل الثغرة
type VulnerabilityDetails struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Location    string `json:"location"`
	Evidence    string `json:"evidence"`
	Impact      string `json:"impact"`
	Solution    string `json:"solution"`
	References  []string `json:"references"`
	CVSS        float64 `json:"cvss"`
	CWE         string `json:"cwe"`
	Scanner     string `json:"scanner"`
	Timestamp   time.Time `json:"timestamp"`
}

// ScannerResult نتيجة الفاحص
type ScannerResult struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Duration    string `json:"duration"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	Findings    int    `json:"findings"`
}

// EnvironmentInfo معلومات البيئة
type EnvironmentInfo struct {
	OS          string `json:"os"`
	Version     string `json:"version"`
	Scanners    []string `json:"scanners"`
	Config      map[string]interface{} `json:"config"`
}

// NewEnhancedReporter ينشئ منشئ تقارير محسن جديد
func NewEnhancedReporter(cfg *config.Config) *EnhancedReporter {
	reporter := &EnhancedReporter{
		config:    cfg,
		templates: make(map[string]*template.Template),
		outputDir: cfg.ReportOutputDir,
	}

	// تحميل قوالب التقارير
	reporter.loadTemplates()

	return reporter
}

// GenerateReport ينشئ تقرير محسن
func (r *EnhancedReporter) GenerateReport(scanResults *ScanResults, format ReportFormat) error {
	// إنشاء التقرير المحسن
	report := r.createEnhancedReport(scanResults)

	// إنشاء مجلد التقارير إذا لم يكن موجوداً
	if err := os.MkdirAll(r.outputDir, 0755); err != nil {
		return fmt.Errorf("فشل في إنشاء مجلد التقارير: %v", err)
	}

	// إنشاء اسم الملف
	filename := fmt.Sprintf("report_%s_%s.%s",
		report.Target,
		time.Now().Format("20060102_150405"),
		format)
	filepath := filepath.Join(r.outputDir, filename)

	// حفظ التقرير بالصيغة المطلوبة
	switch format {
	case JSON:
		return r.saveAsJSON(report, filepath)
	case HTML:
		return r.saveAsHTML(report, filepath)
	case PDF:
		return r.saveAsPDF(report, filepath)
	case XML:
		return r.saveAsXML(report, filepath)
	case EXCEL:
		return r.saveAsExcel(report, filepath)
	default:
		return fmt.Errorf("صيغة تقرير غير مدعومة: %s", format)
	}
}

// createEnhancedReport ينشئ تقرير محسن من نتائج الفحص
func (r *EnhancedReporter) createEnhancedReport(results *ScanResults) *EnhancedReport {
	report := &EnhancedReport{
		ID:        generateReportID(),
		Target:    results.Target,
		StartTime: results.StartTime,
		EndTime:   time.Now(),
		Duration:  time.Since(results.StartTime).String(),
	}

	// حساب الإحصائيات
	report.Statistics = r.calculateStatistics(results)

	// تحويل الثغرات
	report.Vulnerabilities = r.enhanceVulnerabilities(results.Vulnerabilities)

	// تجميع نتائج الفاحصات
	report.ScannerResults = r.aggregateScannerResults(results.ScannerResults)

	// إضافة معلومات البيئة
	report.Environment = r.getEnvironmentInfo()

	return report
}

// Helper functions
func (r *EnhancedReporter) loadTemplates() {
	// تحميل قوالب HTML
	htmlTemplate, err := template.ParseFiles("templates/report.html")
	if err != nil {
		logs.LogError(err, "فشل في تحميل قالب HTML")
	}
	r.templates["html"] = htmlTemplate

	// يمكن إضافة المزيد من القوالب هنا
}

func (r *EnhancedReporter) saveAsJSON(report *EnhancedReport, filepath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("فشل في تحويل التقرير إلى JSON: %v", err)
	}

	return os.WriteFile(filepath, data, 0644)
}

func (r *EnhancedReporter) saveAsHTML(report *EnhancedReport, filepath string) error {
	template := r.templates["html"]
	if template == nil {
		return fmt.Errorf("قالب HTML غير موجود")
	}

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("فشل في إنشاء ملف HTML: %v", err)
	}
	defer file.Close()

	return template.Execute(file, report)
}

func (r *EnhancedReporter) saveAsPDF(report *EnhancedReport, filepath string) error {
	// TODO: تنفيذ تصدير PDF
	return fmt.Errorf("تصدير PDF غير منفذ بعد")
}

func (r *EnhancedReporter) saveAsXML(report *EnhancedReport, filepath string) error {
	// TODO: تنفيذ تصدير XML
	return fmt.Errorf("تصدير XML غير منفذ بعد")
}

func (r *EnhancedReporter) saveAsExcel(report *EnhancedReport, filepath string) error {
	// TODO: تنفيذ تصدير Excel
	return fmt.Errorf("تصدير Excel غير منفذ بعد")
}

func (r *EnhancedReporter) calculateStatistics(results *ScanResults) ReportStatistics {
	stats := ReportStatistics{
		SeverityCounts: make(map[string]int),
		TypeCounts:    make(map[string]int),
		ScannerCounts: make(map[string]int),
	}

	// حساب الإحصائيات
	for _, vuln := range results.Vulnerabilities {
		stats.TotalVulnerabilities++
		stats.SeverityCounts[vuln.Severity]++
		stats.TypeCounts[vuln.Type]++
		stats.ScannerCounts[vuln.Scanner]++
	}

	// حساب معدل النجاح
	totalScanners := len(results.ScannerResults)
	successfulScanners := 0
	for _, result := range results.ScannerResults {
		if result.Error == nil {
			successfulScanners++
		}
	}
	stats.SuccessRate = float64(successfulScanners) / float64(totalScanners) * 100

	return stats
}

func (r *EnhancedReporter) enhanceVulnerabilities(vulns []Vulnerability) []VulnerabilityDetails {
	enhanced := make([]VulnerabilityDetails, len(vulns))
	for i, vuln := range vulns {
		enhanced[i] = VulnerabilityDetails{
			ID:          vuln.ID,
			Name:        vuln.Name,
			Description: vuln.Description,
			Severity:    vuln.Severity,
			Type:        vuln.Type,
			Location:    vuln.Location,
			Evidence:    vuln.Evidence,
			Impact:      vuln.Impact,
			Solution:    vuln.Solution,
			References:  vuln.References,
			CVSS:        vuln.CVSS,
			CWE:         vuln.CWE,
			Scanner:     vuln.Scanner,
			Timestamp:   vuln.Timestamp,
		}
	}
	return enhanced
}

func (r *EnhancedReporter) aggregateScannerResults(results map[string][]Vulnerability) map[string]ScannerResult {
	aggregated := make(map[string]ScannerResult)
	for scanner, vulns := range results {
		aggregated[scanner] = ScannerResult{
			Name:     scanner,
			Findings: len(vulns),
			Status:   "completed",
		}
	}
	return aggregated
}

func (r *EnhancedReporter) getEnvironmentInfo() EnvironmentInfo {
	return EnvironmentInfo{
		OS:      r.config.OS,
		Version: r.config.Version,
		Config:  r.config.ToMap(),
	}
}

func generateReportID() string {
	return fmt.Sprintf("REPORT_%s", time.Now().Format("20060102_150405_999999"))
} 