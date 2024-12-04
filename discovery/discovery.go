package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"vulne_scanner/config"
	"vulne_scanner/logs"
)

// DiscoveryResult يحتوي على نتائج عملية الاكتشاف
type DiscoveryResult struct {
	Subdomains []string            // النطاقات الفرعية المكتشفة
	URLs       []string            // الروابط المكتشفة
	Metadata   map[string]string   // بيانات إضافية
	StartTime  time.Time          // وقت بدء العملية
	Duration   time.Duration      // مدة العملية
}

// DiscoveryOptions خيارات عملية الاكتشاف
type DiscoveryOptions struct {
	Target           string        // الهدف الرئيسي
	Timeout          time.Duration // مهلة العملية
	MaxDepth         int          // عمق البحث عن الروابط
	SubdomainScan    bool         // تفعيل البحث عن النطاقات الفرعية
	URLScan         bool         // تفعيل البحث عن الروابط
	Concurrent      int          // عدد العمليات المتزامنة
	FollowRedirect  bool         // تتبع إعادة التوجيه
	IncludeJS       bool         // تضمين ملفات JavaScript
}

// Discovery المكون الرئيسي لعملية الاكتشاف
type Discovery struct {
	options    *DiscoveryOptions
	subFinder  *SubdomainFinder
	urlCollector *URLCollector
	results    *DiscoveryResult
	mu         sync.Mutex
}

// NewDiscovery ينشئ نسخة جديدة من Discovery
func NewDiscovery(opts *DiscoveryOptions) *Discovery {
	return &Discovery{
		options: opts,
		subFinder: NewSubdomainFinder(opts.Target, opts.Concurrent),
		urlCollector: NewURLCollector(opts.Target, opts.MaxDepth),
		results: &DiscoveryResult{
			Metadata: make(map[string]string),
			StartTime: time.Now(),
		},
	}
}

// Run يبدأ عملية الاكتشاف
func (d *Discovery) Run(ctx context.Context) (*DiscoveryResult, error) {
	logs.LogWarning(fmt.Sprintf("بدء عملية الاكتشاف للهدف: %s", d.options.Target))

	// إنشاء سياق مع مهلة
	ctx, cancel := context.WithTimeout(ctx, d.options.Timeout)
	defer cancel()

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// بدء البحث عن النطاقات الفرعية
	if d.options.SubdomainScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subdomains, err := d.subFinder.Find(ctx)
			if err != nil {
				errChan <- fmt.Errorf("خطأ في البحث عن النطاقات الفرعية: %v", err)
				return
			}
			d.mu.Lock()
			d.results.Subdomains = RemoveDuplicates(subdomains)
			d.mu.Unlock()
		}()
	}

	// بدء جمع الروابط
	if d.options.URLScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls, err := d.urlCollector.Collect(ctx)
			if err != nil {
				errChan <- fmt.Errorf("خطأ في جمع الروابط: %v", err)
				return
			}
			d.mu.Lock()
			d.results.URLs = RemoveDuplicates(urls)
			d.mu.Unlock()
		}()
	}

	// انتظار اكتمال جميع العمليات
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()

	// انتظار النتائج أو حدوث خطأ
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("انتهت مهلة العملية")
	case err := <-errChan:
		return nil, err
	case <-done:
		d.results.Duration = time.Since(d.results.StartTime)
		logs.LogWarning(fmt.Sprintf("اكتملت عملية الاكتشاف. تم العثور على %d نطاق فرعي و %d رابط",
			len(d.results.Subdomains), len(d.results.URLs)))
		return d.results, nil
	}
}

// GetProgress يعيد نسبة تقدم العملية
func (d *Discovery) GetProgress() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	var progress float64
	if d.options.SubdomainScan {
		progress += d.subFinder.GetProgress()
	}
	if d.options.URLScan {
		progress += d.urlCollector.GetProgress()
	}

	totalTasks := 0
	if d.options.SubdomainScan {
		totalTasks++
	}
	if d.options.URLScan {
		totalTasks++
	}

	if totalTasks == 0 {
		return 100
	}

	return progress / float64(totalTasks)
}

// Stop يوقف عملية الاكتشاف
func (d *Discovery) Stop() {
	if d.subFinder != nil {
		d.subFinder.Stop()
	}
	if d.urlCollector != nil {
		d.urlCollector.Stop()
	}
}
