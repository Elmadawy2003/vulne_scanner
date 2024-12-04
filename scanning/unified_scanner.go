package scanning

import (
	"context"
	"fmt"
	"sync"
	"time"

	"vulne_scanner/config"
	"vulne_scanner/logs"
	"vulne_scanner/reports"
)

// UnifiedScanner الفاحص الموحد
type UnifiedScanner struct {
	config     *config.Config
	scanners   map[string]Scanner
	rateLimiter *RateLimiter
	reporter    *reports.Reporter
	mutex       sync.RWMutex
}

// Scanner واجهة الفاحص
type Scanner interface {
	Scan(ctx context.Context, target string) ([]Vulnerability, error)
	Name() string
	Type() string
}

// ScanResult نتيجة الفحص
type ScanResult struct {
	Scanner       string
	Vulnerabilities []Vulnerability
	Duration     time.Duration
	Error        error
}

// NewUnifiedScanner ينشئ فاحص موحد جديد
func NewUnifiedScanner(cfg *config.Config) *UnifiedScanner {
	scanner := &UnifiedScanner{
		config:     cfg,
		scanners:   make(map[string]Scanner),
		rateLimiter: NewRateLimiter(cfg),
		reporter:    reports.NewReporter(cfg),
	}

	// تسجيل الفاحصات
	scanner.registerScanners()

	return scanner
}

// ScanTarget يفحص الهدف باستخدام جميع الفاحصات المناسبة
func (s *UnifiedScanner) ScanTarget(ctx context.Context, target string, options *ScanOptions) (*reports.Report, error) {
	startTime := time.Now()
	logs.LogInfo(fmt.Sprintf("بدء فحص الهدف: %s", target))

	// إنشاء قناة لنتائج الفحص
	results := make(chan ScanResult)
	var wg sync.WaitGroup

	// تشغيل الفاحصات المناسبة بالتوازي
	for name, scanner := range s.getApplicableScanners(target, options) {
		wg.Add(1)
		go func(name string, scanner Scanner) {
			defer wg.Done()
			s.runScanner(ctx, target, scanner, results)
		}(name, scanner)
	}

	// إغلاق قناة النتائج بعد انتهاء جميع الفاحصات
	go func() {
		wg.Wait()
		close(results)
	}()

	// تجميع النتائج
	var allVulnerabilities []Vulnerability
	scannerResults := make(map[string][]Vulnerability)

	for result := range results {
		if result.Error != nil {
			logs.LogError(result.Error, fmt.Sprintf("فشل في الفحص باستخدام %s", result.Scanner))
			continue
		}

		scannerResults[result.Scanner] = result.Vulnerabilities
		allVulnerabilities = append(allVulnerabilities, result.Vulnerabilities...)
	}

	// إنشاء التقرير
	report := &reports.Report{
		Target:         target,
		StartTime:      startTime,
		Duration:      time.Since(startTime),
		Vulnerabilities: allVulnerabilities,
		ScannerResults: scannerResults,
	}

	// حفظ التقرير
	if err := s.reporter.SaveReport(report); err != nil {
		logs.LogError(err, "فشل في حفظ التقرير")
	}

	logs.LogInfo(fmt.Sprintf("اكتمل فحص الهدف: %s، تم العثور على %d ثغرة", target, len(allVulnerabilities)))
	return report, nil
}

// registerScanners يسجل جميع الفاحصات المتاحة
func (s *UnifiedScanner) registerScanners() {
	// فاحصات الويب
	s.scanners["web"] = NewWebScanner(s.config)
	s.scanners["api"] = NewAPIScanner(s.config)
	s.scanners["sql"] = NewSQLScanner(s.config)
	s.scanners["ssl"] = NewSSLScanner(s.config)

	// فاحصات البنية التحتية
	s.scanners["cloud_app"] = NewCloudAppScanner(s.config)
	s.scanners["cloud_service"] = NewCloudServiceScanner(s.config)
	s.scanners["container"] = NewContainerScanner(s.config)
	s.scanners["kubernetes"] = NewKubernetesScanner(s.config)
	s.scanners["iac"] = NewIaCScanner(s.config)

	// فاحصات التطبيقات الحديثة
	s.scanners["serverless"] = NewServerlessScanner(s.config)
	s.scanners["pwa"] = NewPWAScanner(s.config)
	s.scanners["mobile"] = NewMobileScanner(s.config)

	// الفاحصات المتقدمة
	s.scanners["advanced"] = NewAdvancedScanner(s.config)
	s.scanners["waf"] = NewWAFDetector(s.config)
	s.scanners["adaptive"] = NewAdaptiveScanner(s.config)
}

// getApplicableScanners يحدد الفاحصات المناسبة للهدف
func (s *UnifiedScanner) getApplicableScanners(target string, options *ScanOptions) map[string]Scanner {
	applicable := make(map[string]Scanner)

	if options == nil {
		// إذا لم يتم تحديد خيارات، استخدم جميع الفاحصات
		return s.scanners
	}

	// تحديد الفاحصات بناءً على نوع الهدف والخيارات
	for name, scanner := range s.scanners {
		if s.isScannerApplicable(scanner, target, options) {
			applicable[name] = scanner
		}
	}

	return applicable
}

// isScannerApplicable يتحقق مما إذا كان الفاحص مناسباً للهدف
func (s *UnifiedScanner) isScannerApplicable(scanner Scanner, target string, options *ScanOptions) bool {
	// التحقق من نوع الفاحص
	scannerType := scanner.Type()

	// التحقق من الخيارات المحددة
	if options.ScanTypes != nil {
		if !contains(options.ScanTypes, scannerType) {
			return false
		}
	}

	// التحقق من القيود
	if options.ExcludeTypes != nil {
		if contains(options.ExcludeTypes, scannerType) {
			return false
		}
	}

	return true
}

// runScanner يشغل فاحص محدد
func (s *UnifiedScanner) runScanner(ctx context.Context, target string, scanner Scanner, results chan<- ScanResult) {
	startTime := time.Now()
	
	// انتظار معدل الفحص
	if err := s.rateLimiter.Wait(ctx); err != nil {
		results <- ScanResult{
			Scanner: scanner.Name(),
			Error:   fmt.Errorf("تجاوز معدل الفحص: %v", err),
		}
		return
	}

	// تشغيل الفحص
	vulnerabilities, err := scanner.Scan(ctx, target)
	
	results <- ScanResult{
		Scanner:         scanner.Name(),
		Vulnerabilities: vulnerabilities,
		Duration:       time.Since(startTime),
		Error:          err,
	}
}

// ScanOptions خيارات الفحص
type ScanOptions struct {
	ScanTypes     []string
	ExcludeTypes  []string
	Depth         int
	Timeout       time.Duration
	Concurrency   int
	RateLimit     int
	CustomOptions map[string]interface{}
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
} 