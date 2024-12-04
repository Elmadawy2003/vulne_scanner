package types

import "time"

// Vulnerability يمثل ثغرة أمنية
type Vulnerability struct {
	Name        string    // اسم الثغرة
	Type        string    // نوع الثغرة
	Description string    // وصف الثغرة
	Severity    string    // مستوى الخطورة
	CVSS        float64   // درجة CVSS
	CVE         string    // رقم CVE
	CWE         string    // رقم CWE
	Location    string    // موقع الثغرة
	Evidence    string    // دليل الثغرة
	Solution    string    // الحل المقترح
	References  []string  // المراجع
	Found      time.Time // وقت الاكتشاف
}

// Report تقرير الفحص
type Report struct {
	Target          string
	ScanStartTime   time.Time
	ScanEndTime     time.Time
	Duration        time.Duration
	Vulnerabilities []Vulnerability
	Statistics      ReportStatistics
}

// ReportStatistics إحصائيات التقرير
type ReportStatistics struct {
	TotalVulnerabilities int
	CriticalCount        int
	HighCount           int
	MediumCount         int
	LowCount            int
	InfoCount           int
}

// ScanResult نتيجة الفحص
type ScanResult struct {
	Target          string          // الهدف المفحوص
	StartTime       time.Time       // وقت بدء الفحص
	EndTime         time.Time       // وقت انتهاء الفحص
	Duration        time.Duration   // مدة الفحص
	Vulnerabilities []Vulnerability // الثغرات المكتشفة
	Statistics      ScanStatistics  // إحصائيات الفحص
}

// ScanStatistics إحصائيات الفحص
type ScanStatistics struct {
	TotalScans      int     // إجمالي عمليات الفحص
	SuccessfulScans int     // عمليات الفحص الناجحة
	FailedScans     int     // عمليات الفحص الفاشلة
	TotalRequests   int     // إجمالي الطلبات
	RequestRate     float64 // معدل الطلبات في الثانية
	AverageLatency  float64 // متوسط زمن الاستجابة
}

// ScanOptions خيارات الفحص
type ScanOptions struct {
	Target           string        // الهدف
	Timeout          time.Duration // المهلة
	Concurrent       int          // عدد العمليات المتزامنة
	MaxDepth         int          // أقصى عمق للفحص
	FollowRedirects  bool         // تتبع إعادة التوجيه
	IncludeSubdomains bool        // تضمين النطاقات الفرعية
	ExcludedPaths    []string     // المسارات المستثناة
	CustomHeaders    map[string]string // ترويسات مخصصة
} 