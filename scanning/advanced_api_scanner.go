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

// AdvancedAPIScanner فاحص API المتقدم
type AdvancedAPIScanner struct {
	config      *config.Config
	client      *http.Client
	rateLimiter *RateLimiter
	endpoints   map[string]APIEndpoint
	mutex       sync.RWMutex
}

// APIEndpoint معلومات نقط نهاية API
type APIEndpoint struct {
	Path        string
	Method      string
	Parameters  []APIParameter
	Headers     map[string]string
	Auth        bool
	ContentType string
	Schema      interface{}
}

// APIParameter معلومات معامل API
type APIParameter struct {
	Name        string
	Type        string
	Required    bool
	Description string
	Example     interface{}
}

// NewAdvancedAPIScanner ينشئ فاحص API متقدم جديد
func NewAdvancedAPIScanner(cfg *config.Config, rl *RateLimiter) *AdvancedAPIScanner {
	return &AdvancedAPIScanner{
		config:      cfg,
		rateLimiter: rl,
		client:      &http.Client{},
		endpoints:   make(map[string]APIEndpoint),
	}
}

// ScanAPI يفحص API بشكل شامل
func (s *AdvancedAPIScanner) ScanAPI(ctx context.Context, target string) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	// 1. اكتشاف وتحليل مواصفات API
	if err := s.discoverAPISpec(ctx, target); err != nil {
		logs.LogError(err, "فشل في اكتشاف مواصفات API")
	}

	// 2. فحص كل نقطة نهاية
	var wg sync.WaitGroup
	resultChan := make(chan []Vulnerability, len(s.endpoints))
	errorChan := make(chan error, len(s.endpoints))

	for _, endpoint := range s.endpoints {
		wg.Add(1)
		go func(ep APIEndpoint) {
			defer wg.Done()

			// التحكم في معدل الفحص
			if err := s.rateLimiter.Wait(ctx, target); err != nil {
				errorChan <- err
				return
			}

			vulns, err := s.scanAPIEndpoint(ctx, target, ep)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- vulns
		}(endpoint)
	}

	// انتظار انتهاء جميع الفحوصات
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	// تجميع النتائج
	for vulns := range resultChan {
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	// التحقق من الأخطاء
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return vulnerabilities, fmt.Errorf("حدثت أخطاء أثناء فحص API: %v", errors)
	}

	return vulnerabilities, nil
}

// discoverAPISpec يكتشف ويحلل مواصفات API
func (s *AdvancedAPIScanner) discoverAPISpec(ctx context.Context, target string) error {
	// محاولة اكتشاف مواصفات OpenAPI/Swagger
	specPaths := []string{
		"/swagger.json",
		"/api-docs",
		"/openapi.json",
		"/swagger/v1/swagger.json",
		"/api/swagger",
	}

	for _, path := range specPaths {
		url := fmt.Sprintf("%s%s", target, path)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			// تحليل مواصفات API
			if err := s.parseAPISpec(resp.Body); err != nil {
				logs.LogError(err, "فشل في تحليل مواصفات API")
				continue
			}
			return nil
		}
	}

	// إذا لم يتم العثور على مواصفات، نحاول اكتشاف النقاط تلقائياً
	return s.autoDiscoverEndpoints(ctx, target)
}

// parseAPISpec يحلل مواصفات API
func (s *AdvancedAPIScanner) parseAPISpec(reader io.Reader) error {
	var spec map[string]interface{}
	if err := json.NewDecoder(reader).Decode(&spec); err != nil {
		return err
	}

	// تحليل النقاط من المواصفات
	if paths, ok := spec["paths"].(map[string]interface{}); ok {
		for path, methods := range paths {
			if methodMap, ok := methods.(map[string]interface{}); ok {
				for method, details := range methodMap {
					endpoint := APIEndpoint{
						Path:   path,
						Method: strings.ToUpper(method),
					}

					// تحليل المعاملات
					if details, ok := details.(map[string]interface{}); ok {
						if params, ok := details["parameters"].([]interface{}); ok {
							for _, p := range params {
								if param, ok := p.(map[string]interface{}); ok {
									endpoint.Parameters = append(endpoint.Parameters, APIParameter{
										Name:        param["name"].(string),
										Type:        param["type"].(string),
										Required:    param["required"].(bool),
										Description: param["description"].(string),
									})
								}
							}
						}
					}

					s.addEndpoint(endpoint)
				}
			}
		}
	}

	return nil
}

// autoDiscoverEndpoints يكتشف نقاط النهاية تلقائياً
func (s *AdvancedAPIScanner) autoDiscoverEndpoints(ctx context.Context, target string) error {
	// قائمة المسارات الشائعة في API
	commonPaths := []string{
		"/api/v1/",
		"/api/v2/",
		"/api/users",
		"/api/auth",
		"/api/data",
	}

	for _, path := range commonPaths {
		url := fmt.Sprintf("%s%s", target, path)
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			req, err := http.NewRequestWithContext(ctx, method, url, nil)
			if err != nil {
				continue
			}

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				s.addEndpoint(APIEndpoint{
					Path:        path,
					Method:      method,
					ContentType: resp.Header.Get("Content-Type"),
					Auth:        resp.StatusCode == http.StatusUnauthorized,
				})
			}
		}
	}

	return nil
}

// scanAPIEndpoint يفحص نقطة نهاية API معينة
func (s *AdvancedAPIScanner) scanAPIEndpoint(ctx context.Context, target string, endpoint APIEndpoint) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	// 1. فحص التوثيق
	if authVulns := s.checkAPIAuth(ctx, target, endpoint); len(authVulns) > 0 {
		vulnerabilities = append(vulnerabilities, authVulns...)
	}

	// 2. فحص التحكم في الوصول
	if accessVulns := s.checkAccessControl(ctx, target, endpoint); len(accessVulns) > 0 {
		vulnerabilities = append(vulnerabilities, accessVulns...)
	}

	// 3. فحص معالجة المدخلات
	if inputVulns := s.checkInputHandling(ctx, target, endpoint); len(inputVulns) > 0 {
		vulnerabilities = append(vulnerabilities, inputVulns...)
	}

	// 4. فحص معالجة الأخطاء
	if errorVulns := s.checkErrorHandling(ctx, target, endpoint); len(errorVulns) > 0 {
		vulnerabilities = append(vulnerabilities, errorVulns...)
	}

	// 5. فحص التحكم في المعدل
	if rateVulns := s.checkRateLimiting(ctx, target, endpoint); len(rateVulns) > 0 {
		vulnerabilities = append(vulnerabilities, rateVulns...)
	}

	return vulnerabilities, nil
}

// Helper functions
func (s *AdvancedAPIScanner) addEndpoint(endpoint APIEndpoint) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.endpoints[endpoint.Path] = endpoint
}

func (s *AdvancedAPIScanner) checkAPIAuth(ctx context.Context, target string, endpoint APIEndpoint) []Vulnerability {
	var vulns []Vulnerability

	// فحص التوثيق الأساسي
	req, _ := http.NewRequestWithContext(ctx, endpoint.Method, fmt.Sprintf("%s%s", target, endpoint.Path), nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()

	// التحقق من وجود توثيق
	if !endpoint.Auth && resp.StatusCode != http.StatusUnauthorized {
		vulns = append(vulns, Vulnerability{
			Type:        "API Authentication",
			Severity:    SeverityHigh,
			Description: "نقطة نهاية API بدون توثيق",
			Evidence:    fmt.Sprintf("المسار: %s, الطريقة: %s", endpoint.Path, endpoint.Method),
			Solution:    "تنفيذ آلية توثيق مناسبة",
			CVSS:        8.0,
		})
	}

	return vulns
}

func (s *AdvancedAPIScanner) checkAccessControl(ctx context.Context, target string, endpoint APIEndpoint) []Vulnerability {
	var vulns []Vulnerability

	// فحص IDOR
	if strings.Contains(endpoint.Path, "id") || strings.Contains(endpoint.Path, "user") {
		// محاولة الوصول لموارد مختلفة
		ids := []string{"1", "2", "admin", "test"}
		for _, id := range ids {
			path := strings.Replace(endpoint.Path, "{id}", id, -1)
			req, _ := http.NewRequestWithContext(ctx, endpoint.Method, fmt.Sprintf("%s%s", target, path), nil)
			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				vulns = append(vulns, Vulnerability{
					Type:        "IDOR",
					Severity:    SeverityHigh,
					Description: "��مكانية الوصول المباشر لكائنات أخرى",
					Evidence:    fmt.Sprintf("المسار: %s, المعرف: %s", path, id),
					Solution:    "تنفيذ التحقق من الصلاحيات بشكل صحيح",
					CVSS:        7.5,
				})
				break
			}
		}
	}

	return vulns
}

func (s *AdvancedAPIScanner) checkInputHandling(ctx context.Context, target string, endpoint APIEndpoint) []Vulnerability {
	var vulns []Vulnerability

	// فحص حقن SQL
	sqlPayloads := []string{
		"' OR '1'='1",
		"1; DROP TABLE users--",
		"1 UNION SELECT * FROM users--",
	}

	for _, payload := range sqlPayloads {
		req, _ := http.NewRequestWithContext(ctx, endpoint.Method, fmt.Sprintf("%s%s", target, endpoint.Path), nil)
		q := req.URL.Query()
		for _, param := range endpoint.Parameters {
			q.Add(param.Name, payload)
		}
		req.URL.RawQuery = q.Encode()

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "SQL") || strings.Contains(string(body), "database") {
			vulns = append(vulns, Vulnerability{
				Type:        "SQL Injection",
				Severity:    SeverityCritical,
				Description: "نقطة نهاية API معرضة لحقن SQL",
				Evidence:    fmt.Sprintf("المسار: %s, الحمولة: %s", endpoint.Path, payload),
				Solution:    "استخدام الاستعلامات المجهزة مسبقاً والتحقق من صحة المدخلات",
				CVSS:        9.0,
			})
			break
		}
	}

	return vulns
}

func (s *AdvancedAPIScanner) checkErrorHandling(ctx context.Context, target string, endpoint APIEndpoint) []Vulnerability {
	var vulns []Vulnerability

	// إرسال طلبات غير صالحة
	invalidPayloads := []string{
		"{'invalid': json}",
		"<script>alert(1)</script>",
		"../../../etc/passwd",
	}

	for _, payload := range invalidPayloads {
		req, _ := http.NewRequestWithContext(ctx, endpoint.Method, fmt.Sprintf("%s%s", target, endpoint.Path), strings.NewReader(payload))
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "stack trace") || strings.Contains(string(body), "error:") {
			vulns = append(vulns, Vulnerability{
				Type:        "Information Disclosure",
				Severity:    SeverityMedium,
				Description: "كشف معلومات حساسة في رسائل الخطأ",
				Evidence:    fmt.Sprintf("المسار: %s, الاستجابة: %s", endpoint.Path, string(body)),
				Solution:    "تنفيذ معالجة أخطاء آمنة وعدم كشف معلومات حساسة",
				CVSS:        5.0,
			})
			break
		}
	}

	return vulns
}

func (s *AdvancedAPIScanner) checkRateLimiting(ctx context.Context, target string, endpoint APIEndpoint) []Vulnerability {
	var vulns []Vulnerability

	// إرسال طلبات متعددة بسرعة
	start := time.Now()
	successCount := 0
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequestWithContext(ctx, endpoint.Method, fmt.Sprintf("%s%s", target, endpoint.Path), nil)
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			successCount++
		}
	}
	duration := time.Since(start)

	// التحقق من معدل النجاح والوقت
	if successCount > 40 && duration < time.Second*2 {
		vulns = append(vulns, Vulnerability{
			Type:        "Rate Limiting",
			Severity:    SeverityMedium,
			Description: "عدم وجود تحكم في معدل الطلبات",
			Evidence:    fmt.Sprintf("نجح %d طلب في %v", successCount, duration),
			Solution:    "تنفيذ تحكم في معدل الطلبات لمنع إساءة الاستخدام",
			CVSS:        5.0,
		})
	}

	return vulns
} 