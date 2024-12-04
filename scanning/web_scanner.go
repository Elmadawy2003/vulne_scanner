package scanning

import (
    "context"
    "fmt"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "time"

    "vulne_scanner/config"
    "vulne_scanner/logs"
)

// WebScanner مسؤول عن فحص تطبيقات الويب
type WebScanner struct {
    *BaseTool
    client        *http.Client
    endpoints     []string
    payloads      map[VulnerabilityType][]string
    headers       map[string]string
    maxDepth      int
    foundURLs     map[string]bool
    mu            sync.RWMutex
}

// NewWebScanner ينشئ نسخة جديدة من WebScanner
func NewWebScanner() *WebScanner {
    ws := &WebScanner{
        BaseTool:    NewBaseTool("WebScanner", "فاحص تطبيقات الويب المتقدم"),
        endpoints:   make([]string, 0),
        payloads:    DefaultPayloads(),
        headers:     make(map[string]string),
        foundURLs:   make(map[string]bool),
        maxDepth:    3,
    }

    // إعداد العميل HTTP
    ws.client = &http.Client{
        Timeout: 10 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= ws.maxDepth {
                return http.ErrUseLastResponse
            }
            return nil
        },
    }

    return ws
}

// Initialize تهيئة الفاحص
func (ws *WebScanner) Initialize(cfg *config.Config) error {
    if err := ws.BaseTool.Initialize(cfg); err != nil {
        return err
    }

    // تحميل الإعدادات
    ws.maxDepth = cfg.Scanning.MaxDepth
    ws.headers["User-Agent"] = cfg.Security.UserAgent

    // تحميل نقاط النهاية المعروفة
    ws.loadEndpoints()

    return nil
}

// Scan تنفيذ الفحص
func (ws *WebScanner) Scan(ctx context.Context, target string) ([]Vulnerability, error) {
    baseURL, err := url.Parse(target)
    if err != nil {
        return nil, fmt.Errorf("عنوان URL غير صالح: %v", err)
    }

    var vulns []Vulnerability
    var wg sync.WaitGroup
    vulnChan := make(chan Vulnerability, 100)
    errChan := make(chan error, 100)

    // فحص نقاط النهاية المعروفة
    for _, endpoint := range ws.endpoints {
        wg.Add(1)
        go func(ep string) {
            defer wg.Done()
            targetURL := ws.buildURL(baseURL, ep)
            if vs, err := ws.scanEndpoint(ctx, targetURL); err != nil {
                errChan <- err
            } else {
                for _, v := range vs {
                    vulnChan <- v
                }
            }
        }(endpoint)
    }

    // جمع النتائج
    go func() {
        wg.Wait()
        close(vulnChan)
        close(errChan)
    }()

    // معالجة النتائج والأخطاء
    for {
        select {
        case vuln, ok := <-vulnChan:
            if !ok {
                return vulns, nil
            }
            vulns = append(vulns, vuln)
            ws.updateProgress(float64(len(vulns)) / float64(len(ws.endpoints)) * 100)

        case err := <-errChan:
            logs.LogError(err, "خطأ في فحص نقطة نهاية")

        case <-ctx.Done():
            return vulns, ctx.Err()
        }
    }
}

// scanEndpoint فحص نقطة نهاية محددة
func (ws *WebScanner) scanEndpoint(ctx context.Context, targetURL string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    // فحص XSS
    if xssVulns := ws.checkXSS(ctx, targetURL); len(xssVulns) > 0 {
        vulns = append(vulns, xssVulns...)
    }

    // فحص SQL Injection
    if sqlVulns := ws.checkSQLInjection(ctx, targetURL); len(sqlVulns) > 0 {
        vulns = append(vulns, sqlVulns...)
    }

    // فحص CSRF
    if csrfVuln := ws.checkCSRF(ctx, targetURL); csrfVuln != nil {
        vulns = append(vulns, *csrfVuln)
    }

    // فحص Headers
    if headerVulns := ws.checkSecurityHeaders(ctx, targetURL); len(headerVulns) > 0 {
        vulns = append(vulns, headerVulns...)
    }

    return vulns, nil
}

// checkXSS فحص ثغرات XSS
func (ws *WebScanner) checkXSS(ctx context.Context, targetURL string) []Vulnerability {
    var vulns []Vulnerability
    for _, payload := range ws.payloads[XSS] {
        req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
        if err != nil {
            continue
        }

        // إضافة payload في المعلمات
        q := req.URL.Query()
        q.Add("test", payload)
        req.URL.RawQuery = q.Encode()

        resp, err := ws.client.Do(req)
        if err != nil {
            continue
        }
        defer resp.Body.Close()

        // التحقق من وجود الـ payload في الاستجابة
        if ws.containsPayload(resp, payload) {
            vuln := NewVulnerabilityBuilder().
                WithType(XSS).
                WithName("Cross-Site Scripting (XSS)").
                WithDescription("تم اكتشاف إمكانية حقن JavaScript").
                WithSeverity("high").
                WithURL(targetURL).
                WithProof(payload).
                Build()
            vulns = append(vulns, *vuln)
        }
    }
    return vulns
}

// checkSQLInjection فحص ثغرات SQL Injection
func (ws *WebScanner) checkSQLInjection(ctx context.Context, targetURL string) []Vulnerability {
    var vulns []Vulnerability
    for _, payload := range ws.payloads[SQLInjection] {
        req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
        if err != nil {
            continue
        }

        q := req.URL.Query()
        q.Add("id", payload)
        req.URL.RawQuery = q.Encode()

        resp, err := ws.client.Do(req)
        if err != nil {
            continue
        }
        defer resp.Body.Close()

        // التحقق من وجود رسائل خطأ SQL
        if ws.containsSQLError(resp) {
            vuln := NewVulnerabilityBuilder().
                WithType(SQLInjection).
                WithName("SQL Injection").
                WithDescription("تم اكتشاف إمكانية حقن SQL").
                WithSeverity("critical").
                WithURL(targetURL).
                WithProof(payload).
                Build()
            vulns = append(vulns, *vuln)
        }
    }
    return vulns
}

// checkSecurityHeaders فحص ترويسات الأمان
func (ws *WebScanner) checkSecurityHeaders(ctx context.Context, targetURL string) []Vulnerability {
    var vulns []Vulnerability
    
    req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
    if err != nil {
        return vulns
    }

    resp, err := ws.client.Do(req)
    if err != nil {
        return vulns
    }
    defer resp.Body.Close()

    // التحقق من الترويسات الأمنية المهمة
    securityHeaders := map[string]string{
        "X-Frame-Options":        "DENY,SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection":       "1; mode=block",
        "Content-Security-Policy": "",
        "Strict-Transport-Security": "",
    }

    for header, expectedValue := range securityHeaders {
        if value := resp.Header.Get(header); value == "" {
            vuln := NewVulnerabilityBuilder().
                WithType(InsecureHeaders).
                WithName(fmt.Sprintf("Missing Security Header: %s", header)).
                WithDescription(fmt.Sprintf("الترويسة الأمنية %s غير موجودة", header)).
                WithSeverity("medium").
                WithURL(targetURL).
                Build()
            vulns = append(vulns, *vuln)
        } else if expectedValue != "" && !strings.Contains(expectedValue, value) {
            vuln := NewVulnerabilityBuilder().
                WithType(InsecureHeaders).
                WithName(fmt.Sprintf("Insecure Header Value: %s", header)).
                WithDescription(fmt.Sprintf("قيمة الترويسة %s غير آمنة", header)).
                WithSeverity("low").
                WithURL(targetURL).
                Build()
            vulns = append(vulns, *vuln)
        }
    }

    return vulns
}

// DefaultPayloads يعيد قائمة افتراضية من الـ payloads
func DefaultPayloads() map[VulnerabilityType][]string {
    return map[VulnerabilityType][]string{
        XSS: {
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "'\"><script>alert(1)</script>",
        },
        SQLInjection: {
            "' OR '1'='1",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
        },
    }
}

// buildURL بناء URL كامل
func (ws *WebScanner) buildURL(base *url.URL, path string) string {
    u, err := url.Parse(path)
    if err != nil {
        return ""
    }
    return base.ResolveReference(u).String()
}

// loadEndpoints تحميل نقاط النهاية المعروفة
func (ws *WebScanner) loadEndpoints() {
    ws.endpoints = []string{
        "/",
        "/admin",
        "/login",
        "/api",
        "/upload",
        "/search",
        "/profile",
        "/settings",
        "/register",
        "/forgot-password",
    }
} 