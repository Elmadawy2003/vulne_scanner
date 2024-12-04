package scanning

import (
	"context"
	"fmt"
	"sync"
	"time"

	"vulne_scanner/config"
	"vulne_scanner/logs"
)

// RateLimiter متحكم معدل الفحص
type RateLimiter struct {
	config         *config.Config
	requestCount   map[string]int
	requestTimes   map[string][]time.Time
	mutex          sync.RWMutex
	cleanupTicker  *time.Ticker
	maxRequests    int
	timeWindow     time.Duration
	delayBetween   time.Duration
}

// NewRateLimiter ينشئ متحكم معدل جديد
func NewRateLimiter(cfg *config.Config) *RateLimiter {
	rl := &RateLimiter{
		config:       cfg,
		requestCount: make(map[string]int),
		requestTimes: make(map[string][]time.Time),
		maxRequests:  cfg.Scanner.Advanced.RateLimit,
		timeWindow:   time.Minute,
		delayBetween: time.Millisecond * 100,
	}

	// بدء عملية التنظيف الدورية
	rl.cleanupTicker = time.NewTicker(time.Minute)
	go rl.cleanup()

	return rl
}

// Wait ينتظر حتى يمكن إجراء طلب جديد
func (rl *RateLimiter) Wait(ctx context.Context, target string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if rl.canMakeRequest(target) {
				rl.recordRequest(target)
				return nil
			}
			// انتظار قبل المحاولة مرة أخرى
			time.Sleep(rl.delayBetween)
		}
	}
}

// canMakeRequest يتحقق مما إذا كان يمكن إجراء طلب جديد
func (rl *RateLimiter) canMakeRequest(target string) bool {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	count := rl.requestCount[target]
	if count >= rl.maxRequests {
		// التحقق من الطلبات في النافذة الزمنية
		times := rl.requestTimes[target]
		if len(times) == 0 {
			return true
		}

		// إزالة الطلبات القديمة
		now := time.Now()
		windowStart := now.Add(-rl.timeWindow)
		activeRequests := 0
		for _, t := range times {
			if t.After(windowStart) {
				activeRequests++
			}
		}

		return activeRequests < rl.maxRequests
	}

	return true
}

// recordRequest يسجل طلب جديد
func (rl *RateLimiter) recordRequest(target string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	rl.requestCount[target]++
	rl.requestTimes[target] = append(rl.requestTimes[target], now)

	// تسجيل إحصائيات
	if rl.requestCount[target]%100 == 0 {
		logs.LogInfo(fmt.Sprintf("تم إجراء %d طلب على الهدف %s", rl.requestCount[target], target))
	}
}

// cleanup ينظف البيانات القديمة
func (rl *RateLimiter) cleanup() {
	for range rl.cleanupTicker.C {
		rl.mutex.Lock()
		now := time.Now()
		windowStart := now.Add(-rl.timeWindow)

		// تنظيف الطلبات القديمة
		for target, times := range rl.requestTimes {
			var activeTimes []time.Time
			for _, t := range times {
				if t.After(windowStart) {
					activeTimes = append(activeTimes, t)
				}
			}
			if len(activeTimes) > 0 {
				rl.requestTimes[target] = activeTimes
				rl.requestCount[target] = len(activeTimes)
			} else {
				delete(rl.requestTimes, target)
				delete(rl.requestCount, target)
			}
		}
		rl.mutex.Unlock()
	}
}

// Stop يوقف المتحكم
func (rl *RateLimiter) Stop() {
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
}

// GetStats يعيد إحصائيات الطلبات
func (rl *RateLimiter) GetStats(target string) RequestStats {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	times := rl.requestTimes[target]
	count := rl.requestCount[target]

	var rps float64
	if len(times) > 1 {
		duration := times[len(times)-1].Sub(times[0])
		if duration > 0 {
			rps = float64(len(times)) / duration.Seconds()
		}
	}

	return RequestStats{
		TotalRequests: count,
		RequestsPerSecond: rps,
		ActiveWindow: rl.timeWindow,
		CurrentLimit: rl.maxRequests,
	}
}

// RequestStats إحصائيات الطلبات
type RequestStats struct {
	TotalRequests     int
	RequestsPerSecond float64
	ActiveWindow      time.Duration
	CurrentLimit      int
}

// AdjustRateLimit يضبط حد معدل الطلبات
func (rl *RateLimiter) AdjustRateLimit(target string, responseTime time.Duration) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// تعديل المعدل بناءً على وقت الاستجابة
	if responseTime > time.Second {
		// تخفيض المعدل إذا كان وقت الاستجابة طويلاً
		newLimit := int(float64(rl.maxRequests) * 0.8)
		if newLimit < 1 {
			newLimit = 1
		}
		rl.maxRequests = newLimit
		logs.LogWarning(fmt.Sprintf("تخفيض معدل الطلبات إلى %d/دقيقة بسبب بطء الاستجابة", newLimit))
	} else if responseTime < time.Millisecond*100 {
		// زيادة المعدل إذا كانت الاستجابة سريعة
		newLimit := int(float64(rl.maxRequests) * 1.2)
		if newLimit > rl.config.Scanner.Advanced.RateLimit {
			newLimit = rl.config.Scanner.Advanced.RateLimit
		}
		rl.maxRequests = newLimit
		logs.LogInfo(fmt.Sprintf("زيادة معدل الطلبات إلى %d/دقيقة", newLimit))
	}
}

// MonitorTarget يراقب أداء الهدف
func (rl *RateLimiter) MonitorTarget(ctx context.Context, target string) {
	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	var slowResponses int
	var fastResponses int

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := rl.GetStats(target)
			if stats.RequestsPerSecond > float64(rl.maxRequests)/60 {
				slowResponses++
				if slowResponses > 3 {
					// تخفيض المعدل بعد 3 فترات بطيئة متتالية
					rl.maxRequests = int(float64(rl.maxRequests) * 0.7)
					logs.LogWarning(fmt.Sprintf("تخفيض تلقائي لمعدل الطلبات إلى %d/دقيقة", rl.maxRequests))
					slowResponses = 0
				}
			} else {
				fastResponses++
				if fastResponses > 5 {
					// زيادة المعدل بعد 5 فترات سريعة متتالية
					newLimit := int(float64(rl.maxRequests) * 1.3)
					if newLimit <= rl.config.Scanner.Advanced.RateLimit {
						rl.maxRequests = newLimit
						logs.LogInfo(fmt.Sprintf("زيادة تلقائية لمعدل الطلبات إلى %d/دقيقة", rl.maxRequests))
					}
					fastResponses = 0
				}
			}
		}
	}
} 