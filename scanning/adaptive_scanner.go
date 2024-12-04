package scanning

import (
	"context"
	"fmt"
	"sync"
	"time"

	"vulne_scanner/config"
	"vulne_scanner/logs"
)

// AdaptiveScanner الفاحص الذكي المتكيف
type AdaptiveScanner struct {
	config      *config.Config
	rateLimiter *RateLimiter
	patterns    map[string]float64  // نمط الفحص ونسبة نجاحه
	history     map[string][]Result // تاريخ نتائج الفحص
	mutex       sync.RWMutex
}

// Result نتيجة الفحص
type Result struct {
	Pattern     string
	Success     bool
	TimeSpent   time.Duration
	VulnFound   bool
	Timestamp   time.Time
}

// NewAdaptiveScanner ينشئ فاحص ذكي جديد
func NewAdaptiveScanner(cfg *config.Config, rl *RateLimiter) *AdaptiveScanner {
	return &AdaptiveScanner{
		config:      cfg,
		rateLimiter: rl,
		patterns:    make(map[string]float64),
		history:     make(map[string][]Result),
	}
}

// Scan يبدأ عملية الفحص الذكي
func (as *AdaptiveScanner) Scan(ctx context.Context, target string) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	var wg sync.WaitGroup
	resultChan := make(chan Vulnerability, 100)

	// تحليل الهدف وتحديد أفضل أنماط الفحص
	patterns := as.analyzeTarget(ctx, target)

	// تنفيذ الفحص باستخدام الأنماط المحددة
	for pattern, priority := range patterns {
		wg.Add(1)
		go func(p string, prio float64) {
			defer wg.Done()

			// التحكم في معدل الفحص
			if err := as.rateLimiter.Wait(ctx, target); err != nil {
				logs.LogError(err, fmt.Sprintf("خطأ في انتظار معدل الفحص: %v", err))
				return
			}

			start := time.Now()
			vulns, err := as.executeScan(ctx, target, p, prio)
			duration := time.Since(start)

			if err != nil {
				logs.LogError(err, fmt.Sprintf("خطأ في تنفيذ نمط الفحص %s: %v", p, err))
				return
			}

			// تحديث الإحصائيات والتاريخ
			as.updateStats(p, len(vulns) > 0, duration)

			for _, vuln := range vulns {
				resultChan <- vuln
			}
		}(pattern, priority)
	}

	// انتظار انتهاء جميع عمليات الفحص
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// تجميع النتائج
	for vuln := range resultChan {
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// تحليل النتائج وتحديث استراتيجية الفحص
	as.analyzeScanResults(vulnerabilities)

	return vulnerabilities, nil
}

// analyzeTarget يحلل الهدف ويحدد أفضل أنماط الفحص
func (as *AdaptiveScanner) analyzeTarget(ctx context.Context, target string) map[string]float64 {
	as.mutex.RLock()
	defer as.mutex.RUnlock()

	patterns := make(map[string]float64)

	// تحليل تاريخ الفحص
	for pattern, results := range as.history {
		var successRate float64
		var recentSuccess float64
		totalResults := len(results)

		if totalResults > 0 {
			// حساب معدل النجاح العام
			successCount := 0
			for _, result := range results {
				if result.VulnFound {
					successCount++
				}
			}
			successRate = float64(successCount) / float64(totalResults)

			// حساب معدل النجاح الحديث (آخر 5 نتائج)
			recentCount := 0
			startIdx := totalResults - 5
			if startIdx < 0 {
				startIdx = 0
			}
			for _, result := range results[startIdx:] {
				if result.VulnFound {
					recentCount++
				}
			}
			recentSuccess = float64(recentCount) / float64(totalResults-startIdx)
		}

		// حساب الأولوية النهائية
		priority := (successRate*0.4 + recentSuccess*0.6) * as.patterns[pattern]
		patterns[pattern] = priority
	}

	// إضافة أنماط جديدة إذا كان التاريخ فارغاً
	if len(patterns) == 0 {
		patterns = map[string]float64{
			"XSS":              0.8,
			"SQLInjection":     0.8,
			"CommandInjection": 0.7,
			"PathTraversal":    0.6,
			"FileInclusion":    0.6,
			"XXE":              0.5,
			"SSRF":            0.5,
		}
	}

	return patterns
}

// executeScan ينفذ نمط فحص معين
func (as *AdaptiveScanner) executeScan(ctx context.Context, target, pattern string, priority float64) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	// اختيار الفاحص المناسب حسب النمط
	var scanner interface {
		Scan(context.Context, string) ([]Vulnerability, error)
	}

	switch pattern {
	case "XSS":
		scanner = NewXSSScanner(as.config)
	case "SQLInjection":
		scanner = NewSQLScanner(as.config)
	case "CommandInjection":
		scanner = NewCommandInjectionScanner(as.config)
	case "PathTraversal":
		scanner = NewPathTraversalScanner(as.config)
	case "FileInclusion":
		scanner = NewFileInclusionScanner(as.config)
	case "XXE":
		scanner = NewXXEScanner(as.config)
	case "SSRF":
		scanner = NewSSRFScanner(as.config)
	default:
		return nil, fmt.Errorf("نمط فحص غير معروف: %s", pattern)
	}

	// تنفيذ الفحص مع مراعاة الأولوية
	vulns, err := scanner.Scan(ctx, target)
	if err != nil {
		return nil, err
	}

	// تصفية وترتيب النتائج حسب الأولوية
	for _, vuln := range vulns {
		vuln.Score *= priority // تعديل درجة الخطورة حسب أولوية النمط
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

// updateStats يحدث إحصائيات نمط الفحص
func (as *AdaptiveScanner) updateStats(pattern string, success bool, duration time.Duration) {
	as.mutex.Lock()
	defer as.mutex.Unlock()

	// تحديث التاريخ
	result := Result{
		Pattern:   pattern,
		Success:   success,
		TimeSpent: duration,
		Timestamp: time.Now(),
	}
	as.history[pattern] = append(as.history[pattern], result)

	// تحديث نسبة نجاح النمط
	if success {
		as.patterns[pattern] *= 1.1 // زيادة النسبة عند النجاح
		if as.patterns[pattern] > 1.0 {
			as.patterns[pattern] = 1.0
		}
	} else {
		as.patterns[pattern] *= 0.9 // تخفيض النسبة عند الفشل
		if as.patterns[pattern] < 0.1 {
			as.patterns[pattern] = 0.1
		}
	}
}

// analyzeScanResults يحلل نتائج الفحص ويحدث الاستراتيجية
func (as *AdaptiveScanner) analyzeScanResults(vulns []Vulnerability) {
	as.mutex.Lock()
	defer as.mutex.Unlock()

	// تحليل أنواع الثغرات المكتشفة
	vulnTypes := make(map[string]int)
	for _, vuln := range vulns {
		vulnTypes[vuln.Type]++
	}

	// تحديث استراتيجية الفحص بناءً على النتائج
	for vulnType, count := range vulnTypes {
		if count > 0 {
			// زيادة أولوية الأنماط الناجحة
			if pattern, exists := as.patterns[vulnType]; exists {
				as.patterns[vulnType] = pattern * 1.2
				if as.patterns[vulnType] > 1.0 {
					as.patterns[vulnType] = 1.0
				}
			}
		}
	}

	// تسجيل الإحصائيات
	logs.LogInfo(fmt.Sprintf("تم اكتشاف %d ثغرة من %d نوع", len(vulns), len(vulnTypes)))
}

// GetPatternStats يعيد إحصائيات أنماط الفحص
func (as *AdaptiveScanner) GetPatternStats() map[string]PatternStats {
	as.mutex.RLock()
	defer as.mutex.RUnlock()

	stats := make(map[string]PatternStats)
	for pattern, results := range as.history {
		var totalTime time.Duration
		successCount := 0
		vulnCount := 0

		for _, result := range results {
			totalTime += result.TimeSpent
			if result.Success {
				successCount++
			}
			if result.VulnFound {
				vulnCount++
			}
		}

		stats[pattern] = PatternStats{
			TotalRuns:    len(results),
			SuccessRate:  float64(successCount) / float64(len(results)),
			AverageTime:  totalTime / time.Duration(len(results)),
			VulnFound:    vulnCount,
			Priority:     as.patterns[pattern],
		}
	}

	return stats
}

// PatternStats إحصائيات نمط الفحص
type PatternStats struct {
	TotalRuns    int
	SuccessRate  float64
	AverageTime  time.Duration
	VulnFound    int
	Priority     float64
} 