package scanning

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vulne_scanner/config"
	"vulne_scanner/logs"
)

// NucleiScanner مسؤول عن تشغيل وإدارة فحوصات Nuclei
type NucleiScanner struct {
	*BaseTool
	templatePath    string
	customTemplates []string
	severity       []string
	rateLimit      int
	bulkSize       int
	concurrency    int
	templateStats  map[string]int
	results        chan *NucleiResult
	mu             sync.RWMutex
}

// NucleiResult نتيجة فحص Nuclei
type NucleiResult struct {
	TemplateID  string    `json:"template-id"`
	Info        struct {
		Name        string   `json:"name"`
		Author      []string `json:"author"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	Type        string    `json:"type"`
	Host        string    `json:"host"`
	Matched     string    `json:"matched-at"`
	Timestamp   time.Time `json:"timestamp"`
	CURLCommand string    `json:"curl-command"`
	ExtractedResults []string `json:"extracted-results"`
}

// NewNucleiScanner ينشئ نسخة جديدة من NucleiScanner
func NewNucleiScanner(templatePath string) *NucleiScanner {
	ns := &NucleiScanner{
		BaseTool:      NewBaseTool("Nuclei", "أداة فحص الثغرات المعتمدة على القوالب"),
		templatePath:  templatePath,
		severity:      []string{"critical", "high", "medium"},
		rateLimit:     150,
		bulkSize:      25,
		concurrency:   25,
		templateStats: make(map[string]int),
		results:       make(chan *NucleiResult, 100),
	}
	return ns
}

// Initialize تهيئة الماسح
func (ns *NucleiScanner) Initialize(cfg *config.Config) error {
	if err := ns.BaseTool.Initialize(cfg); err != nil {
		return err
	}

	// التحقق من وجود Nuclei
	if _, err := exec.LookPath("nuclei"); err != nil {
		return fmt.Errorf("Nuclei غير مثبت: %v", err)
	}

	// تحميل القوالب المخصصة
	if ns.templatePath != "" {
		templates, err := filepath.Glob(filepath.Join(ns.templatePath, "*.yaml"))
		if err != nil {
			return fmt.Errorf("فشل في تحميل القوالب: %v", err)
		}
		ns.customTemplates = templates
	}

	return nil
}

// Scan تنفيذ الفحص باستخدام Nuclei
func (ns *NucleiScanner) Scan(ctx context.Context, target string) ([]Vulnerability, error) {
	args := ns.buildScanArgs(target)

	// إنشاء وتنفيذ الأمر
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("فشل في إعداد Nuclei: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("فشل في بدء Nuclei: %v", err)
	}

	// معالجة النتائج في الخلفية
	var vulns []Vulnerability
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		decoder := json.NewDecoder(stdout)
		for decoder.More() {
			var result NucleiResult
			if err := decoder.Decode(&result); err != nil {
				logs.LogError(err, "فشل في قراءة نتيجة Nuclei")
				continue
			}

			vuln := ns.convertResultToVulnerability(&result)
			ns.updateStats(result.Info.Severity)
			vulns = append(vulns, vuln)
			
			// تحديث التقدم
			ns.updateProgress(float64(len(vulns)) / float64(ns.templateStats["total"]) * 100)
		}
	}()

	// انتظار اكتمال الفحص
	if err := cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, fmt.Errorf("فشل في تنفيذ Nuclei: %v", err)
		}
	}

	wg.Wait()
	return vulns, nil
}

// buildScanArgs بناء وسائط سطر الأوامر
func (ns *NucleiScanner) buildScanArgs(target string) []string {
	args := []string{
		"-target", target,
		"-json",
		"-silent",
		"-rate-limit", fmt.Sprintf("%d", ns.rateLimit),
		"-bulk-size", fmt.Sprintf("%d", ns.bulkSize),
		"-c", fmt.Sprintf("%d", ns.concurrency),
	}

	// إضافة مستويات الخطورة
	if len(ns.severity) > 0 {
		args = append(args, "-severity", strings.Join(ns.severity, ","))
	}

	// إضافة القوالب المخصصة
	if len(ns.customTemplates) > 0 {
		args = append(args, "-t")
		args = append(args, ns.customTemplates...)
	}

	return args
}

// convertResultToVulnerability تحويل نتيجة Nuclei إلى ثغرة
func (ns *NucleiScanner) convertResultToVulnerability(result *NucleiResult) Vulnerability {
	return *NewVulnerabilityBuilder().
		WithType(VulnerabilityType(result.Type)).
		WithName(result.Info.Name).
		WithDescription(result.Info.Description).
		WithSeverity(result.Info.Severity).
		WithURL(result.Matched).
		WithTags(result.Info.Tags).
		WithProof(result.CURLCommand).
		Build()
}

// updateStats تحديث إحصائيات الفحص
func (ns *NucleiScanner) updateStats(severity string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.templateStats[severity]++
	ns.templateStats["total"]++
}

// SetSeverity تحديد مستويات الخطورة للفحص
func (ns *NucleiScanner) SetSeverity(severity []string) {
	ns.severity = severity
}

// SetRateLimit تحديد معدل الطلبات
func (ns *NucleiScanner) SetRateLimit(rate int) {
	ns.rateLimit = rate
}

// GetTemplateStats الحصول على إحصائيات القوالب
func (ns *NucleiScanner) GetTemplateStats() map[string]int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	stats := make(map[string]int)
	for k, v := range ns.templateStats {
		stats[k] = v
	}
	return stats
}
