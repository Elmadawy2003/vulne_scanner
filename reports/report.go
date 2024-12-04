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
	"vulne_scanner/types"
)

// Reporter منشئ التقارير
type Reporter struct {
	config *config.Config
}

// NewReporter ينشئ منشئ تقارير جديد
func NewReporter(cfg *config.Config) *Reporter {
	return &Reporter{
		config: cfg,
	}
}

// GenerateReport ينشئ تقرير بالصيغة المطلوبة
func (r *Reporter) GenerateReport(vulns []types.Vulnerability, target string, format string, outputPath string) error {
	report := &types.Report{
		Target:          target,
		ScanStartTime:   time.Now(),
		Vulnerabilities: vulns,
		Statistics:      calculateStatistics(vulns),
	}

	switch format {
	case "html":
		return r.generateHTMLReport(report, outputPath)
	case "json":
		return r.generateJSONReport(report, outputPath)
	default:
		return fmt.Errorf("صيغة التقرير غير مدعومة: %s", format)
	}
}

// generateHTMLReport ينشئ تقرير HTML
func (r *Reporter) generateHTMLReport(report *types.Report, outputPath string) error {
	// قراءة قالب HTML
	tmpl, err := template.ParseFiles("templates/report.html")
	if err != nil {
		return fmt.Errorf("فشل في قراءة قالب HTML: %v", err)
	}

	// إنشاء ملف التقرير
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("فشل في إنشاء ملف التقرير: %v", err)
	}
	defer file.Close()

	// تنفيذ القالب
	if err := tmpl.Execute(file, report); err != nil {
		return fmt.Errorf("فشل في إنشاء تقرير HTML: %v", err)
	}

	logs.LogInfo(fmt.Sprintf("تم إنشاء تقرير HTML في: %s", outputPath))
	return nil
}

// generateJSONReport ينشئ تقرير JSON
func (r *Reporter) generateJSONReport(report *types.Report, outputPath string) error {
	// تحويل التقرير إلى JSON
	jsonData, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		return fmt.Errorf("فشل في تحويل التقرير إلى JSON: %v", err)
	}

	// كتابة الملف
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("فشل في كتابة ملف JSON: %v", err)
	}

	logs.LogInfo(fmt.Sprintf("تم إنشاء تقرير JSON في: %s", outputPath))
	return nil
}

// calculateStatistics يحسب إحصائيات التقرير
func calculateStatistics(vulns []types.Vulnerability) types.ReportStatistics {
	stats := types.ReportStatistics{}
	stats.TotalVulnerabilities = len(vulns)

	for _, vuln := range vulns {
		switch vuln.Severity {
		case "Critical":
			stats.CriticalCount++
		case "High":
			stats.HighCount++
		case "Medium":
			stats.MediumCount++
		case "Low":
			stats.LowCount++
		case "Info":
			stats.InfoCount++
		}
	}

	return stats
}
