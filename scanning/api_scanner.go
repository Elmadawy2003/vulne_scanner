package scanning

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "strings"
    "sync"
    "time"

    "vulne_scanner/config"
    "vulne_scanner/logs"
)

// APIScanner مسؤول عن فحص واجهات API
type APIScanner struct {
    *BaseTool
    client        *http.Client
    endpoints     []string
    methods       []string
    headers       map[string]string
    payloads      map[string][]string
    rateLimit     time.Duration
    mu            sync.RWMutex
}

// APIEndpoint يمثل نقطة نهاية API
type APIEndpoint struct {
    Path        string
    Method      string
    Parameters  []string
    Auth        bool
    RateLimit   bool
    Responses   map[int]string
}

// NewAPIScanner ينشئ نسخة جديدة من APIScanner
func NewAPIScanner() *APIScanner {
    as := &APIScanner{
        BaseTool: NewBaseTool("APIScanner", "فاحص واجهات API"),
        headers:  make(map[string]string),
        payloads: make(map[string][]string),
        methods:  []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
    }

    // إعداد العميل HTTP
    as.client = &http.Client{
        Timeout: time.Second * 10,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    return as
}

// Initialize تهيئة الفاحص
func (as *APIScanner) Initialize(cfg *config.Config) error {
    if cfg == nil {
        return fmt.Errorf("تكوين فارغ")
    }
    
    if err := as.BaseTool.Initialize(cfg); err != nil {
        return err
    }

    // تحميل الإعدادات
    as.rateLimit = time.Second / time.Duration(cfg.Security.MaxRequestRate)
    as.headers["User-Agent"] = cfg.Security.UserAgent

    // تحميل نقاط النهاية المعروفة
    as.loadCommonEndpoints()
    
    return nil
}

// Scan تنفيذ الفحص
func (as *APIScanner) Scan(ctx context.Context, target string) ([]Vulnerability, error) {
    if target == "" {
        return nil, fmt.Errorf("هدف فارغ")
    }
    
    vulns := make([]Vulnerability, 0)
    var wg sync.WaitGroup
    vulnChan := make(chan Vulnerability, 100)
    errChan := make(chan error, 100)

    // فحص كل نقطة نهاية
    for _, endpoint := range as.endpoints {
        for _, method := range as.methods {
            wg.Add(1)
            go func(ep, m string) {
                defer wg.Done()
                time.Sleep(as.rateLimit) // تطبيق حد معدل الطلبات

                if v, err := as.scanEndpoint(ctx, target, ep, m); err != nil {
                    errChan <- err
                } else if v != nil {
                    vulnChan <- *v
                }
            }(endpoint, method)
        }
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
            as.updateProgress(float64(len(vulns)) / float64(len(as.endpoints)*len(as.methods)) * 100)

        case err := <-errChan:
            logs.LogError(err, "خطأ في فحص API")

        case <-ctx.Done():
            return vulns, ctx.Err()
        }
    }
}

// scanEndpoint فحص نقطة نهاية محددة
func (as *APIScanner) scanEndpoint(ctx context.Context, baseURL, endpoint, method string) (*Vulnerability, error) {
    url := fmt.Sprintf("%s%s", baseURL, endpoint)
    
    // إنشاء الطلب
    req, err := http.NewRequestWithContext(ctx, method, url, nil)
    if err != nil {
        return nil, err
    }

    // إضافة الترويسات
    for k, v := range as.headers {
        req.Header.Set(k, v)
    }

    // تنفيذ الطلب
    resp, err := as.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // تحليل الاستجابة
    body, _ := io.ReadAll(resp.Body)
    
    // فحص الثغرات المحتملة
    if vuln := as.analyzeResponse(resp, body, url, method); vuln != nil {
        return vuln, nil
    }

    return nil, nil
}

// analyzeResponse تحليل استجابة API
func (as *APIScanner) analyzeResponse(resp *http.Response, body []byte, url, method string) *Vulnerability {
    // فحص الترويسات الأمنية
    if vuln := as.checkSecurityHeaders(resp, url); vuln != nil {
        return vuln
    }

    // فحص كشف المعلومات
    if vuln := as.checkInfoDisclosure(body, url); vuln != nil {
        return vuln
    }

    // فحص التحكم في الوصول
    if vuln := as.checkAccessControl(resp, url, method); vuln != nil {
        return vuln
    }

    // فحص معدل الطلبات
    if vuln := as.checkRateLimiting(resp, url); vuln != nil {
        return vuln
    }

    return nil
}

// checkSecurityHeaders فحص الترويسات الأمنية
func (as *APIScanner) checkSecurityHeaders(resp *http.Response, url string) *Vulnerability {
    requiredHeaders := map[string]string{
        "Content-Security-Policy": "",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
    }

    for header, expectedValue := range requiredHeaders {
        if value := resp.Header.Get(header); value == "" {
            return NewVulnerabilityBuilder().
                WithType(InsecureHeaders).
                WithName(fmt.Sprintf("Missing Security Header: %s", header)).
                WithDescription(fmt.Sprintf("الترويسة الأمنية %s غير موجودة", header)).
                WithSeverity("medium").
                WithURL(url).
                Build()
        } else if expectedValue != "" && value != expectedValue {
            return NewVulnerabilityBuilder().
                WithType(InsecureHeaders).
                WithName(fmt.Sprintf("Insecure Header Value: %s", header)).
                WithDescription(fmt.Sprintf("قيمة الترويسة %s غير آمنة", header)).
                WithSeverity("low").
                WithURL(url).
                Build()
        }
    }

    return nil
}

// checkInfoDisclosure فحص كشف المعلومات
func (as *APIScanner) checkInfoDisclosure(body []byte, url string) *Vulnerability {
    sensitivePatterns := []string{
        "password", "token", "secret", "key",
        "api_key", "apikey", "api-key",
        "private", "credential",
    }

    bodyStr := string(body)
    for _, pattern := range sensitivePatterns {
        if strings.Contains(strings.ToLower(bodyStr), pattern) {
            return NewVulnerabilityBuilder().
                WithType(SensitiveDataExposure).
                WithName("Sensitive Information Disclosure").
                WithDescription(fmt.Sprintf("تم اكتشاف معلومات حساسة في الاستجابة: %s", pattern)).
                WithSeverity("high").
                WithURL(url).
                WithProof(fmt.Sprintf("تم العثور على النمط: %s", pattern)).
                Build()
        }
    }

    return nil
}

// loadCommonEndpoints تحميل نقاط النهاية الشائعة
func (as *APIScanner) loadCommonEndpoints() {
    as.endpoints = []string{
        "/api",
        "/api/v1",
        "/api/v2",
        "/auth",
        "/login",
        "/users",
        "/admin",
        "/swagger",
        "/docs",
        "/graphql",
        "/health",
        "/metrics",
    }
}

// checkAccessControl فحص التحكم في الوصول
func (as *APIScanner) checkAccessControl(resp *http.Response, url, method string) *Vulnerability {
    // فحص الوصول بدون مصادقة للمسارات المحمية
    if isProtectedPath(url) && resp.StatusCode != http.StatusUnauthorized {
        return NewVulnerabilityBuilder().
            WithType(BrokenAccessControl).
            WithName("Missing Authentication Check").
            WithDescription("تم اكتشاف إمكانية الوصول لمسار محمي بدون مصادقة").
            WithSeverity("critical").
            WithURL(url).
            WithProof(fmt.Sprintf("Method: %s, Status: %d", method, resp.StatusCode)).
            Build()
    }

    // فحص CORS
    if origin := resp.Header.Get("Access-Control-Allow-Origin"); origin == "*" {
        return NewVulnerabilityBuilder().
            WithType(SecurityMisconfig).
            WithName("Insecure CORS Configuration").
            WithDescription("تم اكتشاف تكوين CORS غير آمن").
            WithSeverity("medium").
            WithURL(url).
            WithProof(fmt.Sprintf("Access-Control-Allow-Origin: %s", origin)).
            Build()
    }

    return nil
}

// checkRateLimiting فحص تقييد معدل الطلبات
func (as *APIScanner) checkRateLimiting(resp *http.Response, url string) *Vulnerability {
    rateLimitHeaders := []string{
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Retry-After",
    }

    hasRateLimit := false
    for _, header := range rateLimitHeaders {
        if resp.Header.Get(header) != "" {
            hasRateLimit = true
            break
        }
    }

    if !hasRateLimit {
        return NewVulnerabilityBuilder().
            WithType(SecurityMisconfig).
            WithName("Missing Rate Limiting").
            WithDescription("لم يتم اكتشاف آلية لتقييد معدل الطلبات").
            WithSeverity("medium").
            WithURL(url).
            Build()
    }

    return nil
}

// isProtectedPath التحقق من المسارات المحمية
func isProtectedPath(url string) bool {
    protectedPaths := []string{
        "/admin",
        "/dashboard",
        "/settings",
        "/users",
        "/profile",
        "/api/admin",
        "/api/v1/admin",
        "/api/v2/admin",
    }

    for _, path := range protectedPaths {
        if strings.Contains(strings.ToLower(url), strings.ToLower(path)) {
            return true
        }
    }
    return false
}

// checkJWTSecurity فحص أمان JWT
func (as *APIScanner) checkJWTSecurity(resp *http.Response, url string) *Vulnerability {
    // فحص وجود JWT في الترويسات
    authHeader := resp.Header.Get("Authorization")
    if strings.HasPrefix(authHeader, "Bearer ") {
        token := strings.TrimPrefix(authHeader, "Bearer ")
        
        // فحص الخوارزمية المستخدمة
        if strings.Contains(token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0") {
            return NewVulnerabilityBuilder().
                WithType(WeakCrypto).
                WithName("Insecure JWT Algorithm").
                WithDescription("تم اكتشاف استخدام خوارزمية غير آمنة في JWT").
                WithSeverity("high").
                WithURL(url).
                WithProof("Algorithm: none").
                Build()
        }
    }

    return nil
}

// checkAPIDocumentation فحص وثائق API
func (as *APIScanner) checkAPIDocumentation(resp *http.Response, url string) *Vulnerability {
    docPaths := []string{"/swagger", "/docs", "/openapi.json", "/swagger.json"}
    
    for _, path := range docPaths {
        if strings.Contains(url, path) && resp.StatusCode == http.StatusOK {
            return NewVulnerabilityBuilder().
                WithType(InfoDisclosure).
                WithName("Exposed API Documentation").
                WithDescription("تم اكتشاف وثائق API متاحة للعموم").
                WithSeverity("low").
                WithURL(url).
                Build()
        }
    }

    return nil
}

// checkErrorMessages فحص رسائل الخطأ
func (as *APIScanner) checkErrorMessages(body []byte, url string) *Vulnerability {
    // فحص وجود تفاصيل تقنية في رسائل الخطأ
    sensitiveErrors := []string{
        "sql error",
        "exception",
        "stack trace",
        "debug",
        "line number",
        "syntax error",
    }

    bodyStr := strings.ToLower(string(body))
    for _, errPattern := range sensitiveErrors {
        if strings.Contains(bodyStr, errPattern) {
            return NewVulnerabilityBuilder().
                WithType(InfoDisclosure).
                WithName("Verbose Error Messages").
                WithDescription("تم اكتشاف رسائل خطأ تفصيلية").
                WithSeverity("medium").
                WithURL(url).
                WithProof(fmt.Sprintf("Found pattern: %s", errPattern)).
                Build()
        }
    }

    return nil
}

// checkMethodsAllowed فحص الطرق المسموحة
func (as *APIScanner) checkMethodsAllowed(resp *http.Response, url string) *Vulnerability {
    // فحص الطرق المسموحة من خلال ترويسة OPTIONS
    if methods := resp.Header.Get("Access-Control-Allow-Methods"); methods != "" {
        dangerousMethods := []string{"TRACE", "TRACK", "HEAD"}
        for _, method := range dangerousMethods {
            if strings.Contains(methods, method) {
                return NewVulnerabilityBuilder().
                    WithType(SecurityMisconfig).
                    WithName("Dangerous HTTP Methods Enabled").
                    WithDescription(fmt.Sprintf("تم اكتشاف طريقة HTTP خطرة مفعلة: %s", method)).
                    WithSeverity("medium").
                    WithURL(url).
                    WithProof(fmt.Sprintf("Allowed Methods: %s", methods)).
                    Build()
            }
        }
    }

    return nil
} 
