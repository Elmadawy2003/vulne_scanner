package scanning

import (
    "context"
    "fmt"
    "net/http"
    "path"
    "strings"
    "sync"
    "time"

    "vulne_scanner/config"
    "vulne_scanner/logs"
)

// DirbScanner مسؤول عن فحص المسارات والملفات الحساسة
type DirbScanner struct {
    *BaseTool
    client       *http.Client
    wordlist     []string
    extensions   []string
    maxDepth     int
    concurrent   int
    foundPaths   map[string]bool
    mu           sync.RWMutex
}

// DirbResult نتيجة فحص المسار
type DirbResult struct {
    Path         string
    StatusCode   int
    ContentType  string
    ContentSize  int64
    ResponseTime time.Duration
}

// NewDirbScanner ينشئ نسخة جديدة من DirbScanner
func NewDirbScanner() *DirbScanner {
    ds := &DirbScanner{
        BaseTool:   NewBaseTool("DirbScanner", "فاحص المسارات والملفات الحساسة"),
        maxDepth:   3,
        concurrent: 20,
        foundPaths: make(map[string]bool),
        extensions: []string{
            ".php", ".asp", ".aspx", ".jsp", ".js", ".txt", ".bak",
            ".old", ".backup", ".zip", ".tar", ".gz", ".sql", ".env",
        },
    }

    // إعداد العميل HTTP
    ds.client = &http.Client{
        Timeout: time.Second * 10,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= ds.maxDepth {
                return http.ErrUseLastResponse
            }
            return nil
        },
    }

    return ds
}

// Initialize تهيئة الفاحص
func (ds *DirbScanner) Initialize(cfg *config.Config) error {
    if err := ds.BaseTool.Initialize(cfg); err != nil {
        return err
    }

    // تحميل قائمة الكلمات
    if err := ds.loadWordlist(); err != nil {
        return fmt.Errorf("فشل في تحميل قائمة الكلمات: %v", err)
    }

    return nil
}

// Scan تنفيذ الفحص
func (ds *DirbScanner) Scan(ctx context.Context, target string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var wg sync.WaitGroup
    vulnChan := make(chan Vulnerability, ds.concurrent)
    errChan := make(chan error, ds.concurrent)
    
    // إنشاء قناة للتحكم في التزامن
    semaphore := make(chan struct{}, ds.concurrent)

    // فحص كل مسار
    totalPaths := len(ds.wordlist) * (len(ds.extensions) + 1)
    pathsScanned := 0

    for _, word := range ds.wordlist {
        // فحص المسار نفسه
        wg.Add(1)
        go func(w string) {
            defer wg.Done()
            semaphore <- struct{}{} // حجز مكان
            defer func() { <-semaphore }() // تحرير المكان

            if result, err := ds.scanPath(ctx, target, w); err != nil {
                errChan <- err
            } else if result != nil {
                if vuln := ds.processResult(result); vuln != nil {
                    vulnChan <- *vuln
                }
            }
            pathsScanned++
            ds.updateProgress(float64(pathsScanned) / float64(totalPaths) * 100)
        }(word)

        // فحص المسار مع الامتدادات
        for _, ext := range ds.extensions {
            wg.Add(1)
            go func(w, e string) {
                defer wg.Done()
                semaphore <- struct{}{}
                defer func() { <-semaphore }()

                path := w + e
                if result, err := ds.scanPath(ctx, target, path); err != nil {
                    errChan <- err
                } else if result != nil {
                    if vuln := ds.processResult(result); vuln != nil {
                        vulnChan <- *vuln
                    }
                }
                pathsScanned++
                ds.updateProgress(float64(pathsScanned) / float64(totalPaths) * 100)
            }(word, ext)
        }
    }

    // انتظار اكتمال جميع الفحوصات
    go func() {
        wg.Wait()
        close(vulnChan)
        close(errChan)
    }()

    // جمع النتائج
    for {
        select {
        case vuln, ok := <-vulnChan:
            if !ok {
                return vulns, nil
            }
            vulns = append(vulns, vuln)

        case err := <-errChan:
            logs.LogError(err, "خطأ في فحص المسار")

        case <-ctx.Done():
            return vulns, ctx.Err()
        }
    }
}

// scanPath فحص مسار محدد
func (ds *DirbScanner) scanPath(ctx context.Context, baseURL, path string) (*DirbResult, error) {
    url := fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), strings.TrimLeft(path, "/"))
    
    // تجنب فحص نفس المسار مرتين
    ds.mu.Lock()
    if ds.foundPaths[url] {
        ds.mu.Unlock()
        return nil, nil
    }
    ds.foundPaths[url] = true
    ds.mu.Unlock()

    // إنشاء الطلب
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }

    // تنفيذ الطلب
    start := time.Now()
    resp, err := ds.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // تجميع النتيجة
    result := &DirbResult{
        Path:         path,
        StatusCode:   resp.StatusCode,
        ContentType:  resp.Header.Get("Content-Type"),
        ContentSize:  resp.ContentLength,
        ResponseTime: time.Since(start),
    }

    return result, nil
}

// processResult تحليل نتيجة الفحص
func (ds *DirbScanner) processResult(result *DirbResult) *Vulnerability {
    // تجاهل الاستجابات غير المهمة
    if result.StatusCode == http.StatusNotFound ||
       result.StatusCode == http.StatusForbidden {
        return nil
    }

    // فحص الملفات الحساسة
    if ds.isSensitiveFile(result.Path) {
        return NewVulnerabilityBuilder().
            WithType(InfoDisclosure).
            WithName("Sensitive File Exposure").
            WithDescription(fmt.Sprintf("تم اكتشاف ملف حساس: %s", result.Path)).
            WithSeverity("high").
            WithURL(result.Path).
            Build()
    }

    // فحص المسارات الخطرة
    if ds.isDangerousPath(result.Path) {
        return NewVulnerabilityBuilder().
            WithType(SecurityMisconfig).
            WithName("Dangerous Path Exposed").
            WithDescription(fmt.Sprintf("تم اكتشاف مسار خطر: %s", result.Path)).
            WithSeverity("critical").
            WithURL(result.Path).
            Build()
    }

    return nil
}

// isSensitiveFile التحقق من الملفات الحساسة
func (ds *DirbScanner) isSensitiveFile(filePath string) bool {
    sensitiveFiles := []string{
        ".env", "config.php", "wp-config.php", "web.config",
        ".git", ".svn", ".htaccess", "robots.txt", "sitemap.xml",
        "backup", "dump", "database", "admin", "phpinfo",
    }

    fileName := strings.ToLower(path.Base(filePath))
    for _, sensitive := range sensitiveFiles {
        if strings.Contains(fileName, sensitive) {
            return true
        }
    }
    return false
}

// isDangerousPath التحقق من المسارات الخطرة
func (ds *DirbScanner) isDangerousPath(path string) bool {
    dangerousPaths := []string{
        "/admin", "/phpmyadmin", "/wp-admin", "/console",
        "/shell", "/upload", "/backup", "/test", "/dev",
    }

    pathLower := strings.ToLower(path)
    for _, dangerous := range dangerousPaths {
        if strings.Contains(pathLower, dangerous) {
            return true
        }
    }
    return false
}

// loadWordlist تحميل قائمة الكلمات
func (ds *DirbScanner) loadWordlist() error {
    // يمكن تحميل قائمة الكلمات من ملف أو تضمينها مباشرة
    ds.wordlist = []string{
        "admin", "backup", "config", "db", "debug",
        "dev", "test", "tmp", "temp", "upload",
        "images", "img", "css", "js", "static",
        "api", "login", "register", "user", "admin",
        // يمكن إضافة المزيد من الكلمات
    }
    return nil
} 