package scanning

import (
	"context"
	"fmt"
	"sync"
	"time"

	"vulne_scanner/config"
	"vulne_scanner/logs"
	"vulne_scanner/types"
)

// Scanner الماسح الرئيسي
type Scanner struct {
	config      *config.Config
	tools       []Tool
	rateLimiter *RateLimiter
	mutex       sync.RWMutex
}

// NewScanner ينشئ ماسح جديد
func NewScanner(cfg *config.Config) *Scanner {
	scanner := &Scanner{
		config:      cfg,
		rateLimiter: NewRateLimiter(cfg),
	}

	// تسجيل الأدوات
	scanner.registerTools()

	return scanner
}

// ScanTarget يفحص هدفاً واحداً
func (s *Scanner) ScanTarget(ctx context.Context, target string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:    target,
		StartTime: time.Now(),
	}

	// تشغيل جميع الأدوات
	var wg sync.WaitGroup
	vulnChan := make(chan []types.Vulnerability)
	errChan := make(chan error)

	for _, tool := range s.tools {
		wg.Add(1)
		go func(t Tool) {
			defer wg.Done()

			// انتظار معدل الفحص
			if err := s.rateLimiter.Wait(ctx); err != nil {
				errChan <- fmt.Errorf("تجاوز معدل الفحص: %v", err)
				return
			}

			// تشغيل الأداة
			vulns, err := t.Run(ctx, target)
			if err != nil {
				errChan <- fmt.Errorf("فشل في تشغيل الأداة %s: %v", t.Name(), err)
				return
			}

			vulnChan <- vulns
		}(tool)
	}

	// تجميع النتائج
	go func() {
		wg.Wait()
		close(vulnChan)
		close(errChan)
	}()

	// معالجة النتائج والأخطاء
	for {
		select {
		case vulns, ok := <-vulnChan:
			if !ok {
				result.EndTime = time.Now()
				result.Duration = result.EndTime.Sub(result.StartTime)
				return result, nil
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vulns...)

		case err := <-errChan:
			logs.LogError(err, "خطأ في تنفيذ إحدى الأدوات")

		case <-ctx.Done():
			return result, ctx.Err()
		}
	}
}

// ScanTargets يفحص مجموعة من الأهداف
func (s *Scanner) ScanTargets(ctx context.Context, targets []string) ([]*types.ScanResult, error) {
	var results []*types.ScanResult
	var wg sync.WaitGroup
	resultChan := make(chan *types.ScanResult)
	errChan := make(chan error)

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			result, err := s.ScanTarget(ctx, t)
			if err != nil {
				errChan <- fmt.Errorf("فشل في فحص الهدف %s: %v", t, err)
				return
			}

			resultChan <- result
		}(target)
	}

	// تجميع النتائج
	go func() {
		wg.Wait()
		close(resultChan)
		close(errChan)
	}()

	// معالجة النتائج والأخطاء
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				return results, nil
			}
			results = append(results, result)

		case err := <-errChan:
			logs.LogError(err, "خطأ في فحص أحد الأهداف")

		case <-ctx.Done():
			return results, ctx.Err()
		}
	}
}

// registerTools يسجل الأدوات المتاحة
func (s *Scanner) registerTools() {
	s.tools = []Tool{
		NewWebScanner(s.config),
		NewPortScanner(s.config),
		NewSSLScanner(s.config),
		NewAPIScanner(s.config),
		NewSQLScanner(s.config),
		NewDirbScanner(s.config),
		NewNucleiScanner(s.config),
		NewAdvancedScanner(s.config),
		NewModernAppScanner(s.config),
		NewCloudScanner(s.config),
		NewContainerScanner(s.config),
		NewKubernetesScanner(s.config),
	}
}

// Stop يوقف جميع عمليات الفحص
func (s *Scanner) Stop() {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, tool := range s.tools {
		tool.Stop()
	}
}

// GetProgress يعيد نسبة تقدم الفحص
func (s *Scanner) GetProgress() float64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if len(s.tools) == 0 {
		return 0
	}

	var total float64
	for _, tool := range s.tools {
		total += tool.GetProgress()
	}

	return total / float64(len(s.tools))
}
