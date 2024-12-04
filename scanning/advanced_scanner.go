package scanning

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"vulne_scanner/config"
	"vulne_scanner/logs"
)

// AdvancedScanner وحدة الفحص المتقدم
type AdvancedScanner struct {
	config     *config.Config
	client     *http.Client
	concurrent int
	patterns   map[string][]*regexp.Regexp
	signatures map[string][]string
	waf        *WAFDetector
}

// NewAdvancedScanner ينشئ فاحص متقدم جديد
func NewAdvancedScanner(cfg *config.Config, concurrent int) *AdvancedScanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.Scanner.Advanced.VerifySSL,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Scanner.Advanced.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.Scanner.Advanced.MaxRedirects {
				return fmt.Errorf("تم تجاوز الحد الأقصى لإعادة التوجيه (%d)", cfg.Scanner.Advanced.MaxRedirects)
			}
			return nil
		},
	}

	return &AdvancedScanner{
		config:     cfg,
		client:     client,
		concurrent: concurrent,
		patterns:   loadVulnerabilityPatterns(),
		signatures: loadVulnerabilitySignatures(),
		waf:        NewWAFDetector(),
	}
}

// ScanTarget يقوم بفحص شامل للهدف
func (s *AdvancedScanner) ScanTarget(ctx context.Context, target string) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	var mu sync.Mutex
	var wg sync.WaitGroup

	// التحقق من وجود WAF
	if wafInfo := s.waf.DetectWAF(ctx, target); wafInfo != nil {
		logs.LogInfo(fmt.Sprintf("تم اكتشاف WAF: %s على الهدف %s", wafInfo.Name, target))
		vulnerabilities = append(vulnerabilities, *s.createWAFVulnerability(wafInfo))
	}

	// فحص الإعدادات الخاطئة
	if misconfig := s.checkMisconfigurations(ctx, target); misconfig != nil {
		vulnerabilities = append(vulnerabilities, *misconfig)
	}

	// فحص نقاط النهاية API
	apiEndpoints := s.discoverAPIEndpoints(ctx, target)
	for _, endpoint := range apiEndpoints {
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			if vuln := s.checkAPIVulnerabilities(ctx, ep); vuln != nil {
				mu.Lock()
				vulnerabilities = append(vulnerabilities, *vuln)
				mu.Unlock()
			}
		}(endpoint)
	}

	// فحص ثغرات JWT
	if jwtVuln := s.checkJWTVulnerabilities(ctx, target); jwtVuln != nil {
		vulnerabilities = append(vulnerabilities, *jwtVuln)
	}

	// فحص ثغرات GraphQL
	if graphqlVuln := s.checkGraphQLVulnerabilities(ctx, target); graphqlVuln != nil {
		vulnerabilities = append(vulnerabilities, *graphqlVuln)
	}

	// فحص ثغرات CORS
	if corsVuln := s.checkCORSMisconfigurations(ctx, target); corsVuln != nil {
		vulnerabilities = append(vulnerabilities, *corsVuln)
	}

	// فحص ثغرات الذاكرة
	if memVuln := s.checkMemoryLeaks(ctx, target); memVuln != nil {
		vulnerabilities = append(vulnerabilities, *memVuln)
	}

	// فحص ثغرات التوثيق
	if authVuln := s.checkAuthenticationVulnerabilities(ctx, target); authVuln != nil {
		vulnerabilities = append(vulnerabilities, *authVuln)
	}

	// فحص ثغرات التخزين المؤقت
	if cacheVuln := s.checkCacheVulnerabilities(ctx, target); cacheVuln != nil {
		vulnerabilities = append(vulnerabilities, *cacheVuln)
	}

	wg.Wait()
	return vulnerabilities, nil
}

// checkMisconfigurations يفحص الإعدادات الخاطئة
func (s *AdvancedScanner) checkMisconfigurations(ctx context.Context, target string) *Vulnerability {
	configs := []struct {
		path        string
		pattern     string
		description string
		severity    string
	}{
		{".git/config", "repositoryformatversion", "تم اكتشاف مجلد .git مكشوف", SeverityHigh},
		{".env", "APP_", "تم اكتشاف ملف .env مكشوف", SeverityCritical},
		{"wp-config.php", "DB_PASSWORD", "تم اكتشاف ملف wp-config.php مكشوف", SeverityCritical},
		{"config.php", "password", "تم اكتشاف ملف config.php مكشوف", SeverityHigh},
		{"debug.log", "error", "تم اكتشاف ملف debug.log مكشوف", SeverityMedium},
	}

	for _, config := range configs {
		url := fmt.Sprintf("%s/%s", target, config.path)
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
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			if strings.Contains(string(body), config.pattern) {
				return &Vulnerability{
					Type:        "Misconfiguration",
					Severity:    config.severity,
					Description: config.description,
					Evidence:    fmt.Sprintf("تم العثور على الملف في: %s", url),
					Solution:    "قم بمنع الوصول إلى هذا الملف أو إزالته من الخادم",
					CVSS:        8.0,
					References: []string{
						"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
					},
					Location: url,
				}
			}
		}
	}

	return nil
}

// checkAPIVulnerabilities يفحص ثغرات API
func (s *AdvancedScanner) checkAPIVulnerabilities(ctx context.Context, endpoint string) *Vulnerability {
	// فحص IDOR
	if vuln := s.checkIDOR(ctx, endpoint); vuln != nil {
		return vuln
	}

	// فحص Mass Assignment
	if vuln := s.checkMassAssignment(ctx, endpoint); vuln != nil {
		return vuln
	}

	// فحص Rate Limiting
	if vuln := s.checkRateLimiting(ctx, endpoint); vuln != nil {
		return vuln
	}

	return nil
}

// checkJWTVulnerabilities يفحص ثغرات JWT
func (s *AdvancedScanner) checkJWTVulnerabilities(ctx context.Context, target string) *Vulnerability {
	weakAlgorithms := []string{"none", "HS256"}
	for _, alg := range weakAlgorithms {
		token := s.createTestJWT(alg)
		req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return &Vulnerability{
				Type:        "JWT",
				Severity:    SeverityHigh,
				Description: "تم اكتشاف قبول توقيع JWT ضعيف",
				Evidence:    fmt.Sprintf("تم قبول JWT مع خوارزمية %s", alg),
				Solution:    "استخدم خوارزميات توقيع قوية مثل RS256",
				CVSS:        7.5,
				References: []string{
					"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
				},
				Location: target,
			}
		}
	}

	return nil
}

// checkGraphQLVulnerabilities يفحص ثغرات GraphQL
func (s *AdvancedScanner) checkGraphQLVulnerabilities(ctx context.Context, target string) *Vulnerability {
	introspectionQuery := `{"query":"query{__schema{types{name,fields{name}}}}"}`
	req, _ := http.NewRequestWithContext(ctx, "POST", target+"/graphql", strings.NewReader(introspectionQuery))
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "__schema") {
		return &Vulnerability{
			Type:        "GraphQL",
			Severity:    SeverityMedium,
			Description: "تم اكتشاف استعلام Introspection مفعل",
			Evidence:    "الخادم يسمح باستعلامات Introspection",
			Solution:    "قم بتعطيل استعلامات Introspection في بيئة الإنتاج",
			CVSS:        5.0,
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			},
			Location: target + "/graphql",
		}
	}

	return nil
}

// checkCORSMisconfigurations يفحص ثغرات CORS
func (s *AdvancedScanner) checkCORSMisconfigurations(ctx context.Context, target string) *Vulnerability {
	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	req.Header.Set("Origin", "https://evil.com")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if origin := resp.Header.Get("Access-Control-Allow-Origin"); origin == "*" || origin == "https://evil.com" {
		return &Vulnerability{
			Type:        "CORS",
			Severity:    SeverityHigh,
			Description: "تم اكتشاف تكوين CORS غير آمن",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s", origin),
			Solution:    "قم بتقييد Access-Control-Allow-Origin للنطاقات الموثوقة فقط",
			CVSS:        6.5,
			References: []string{
				"https://portswigger.net/web-security/cors",
			},
			Location: target,
		}
	}

	return nil
}

// checkMemoryLeaks يفحص تسريبات الذاكرة
func (s *AdvancedScanner) checkMemoryLeaks(ctx context.Context, target string) *Vulnerability {
	patterns := []struct {
		regex       string
		description string
	}{
		{`(?i)(exception|error|stack trace|debug)`, "تم اكتشاف رسائل خطأ مفصلة"},
		{`(?i)(internal server error|memory dump)`, "تم اكتشاف تسريب معلومات الخادم"},
		{`(?i)(SELECT|INSERT|UPDATE|DELETE|UNION).*(?i)(FROM|INTO|WHERE)`, "تم اكتشاف استعلامات SQL في الاستجابة"},
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	for _, pattern := range patterns {
		if match, _ := regexp.MatchString(pattern.regex, string(body)); match {
			return &Vulnerability{
				Type:        "Information Disclosure",
				Severity:    SeverityMedium,
				Description: pattern.description,
				Evidence:    "تم العثور على معلومات حساسة في استجابة الخادم",
				Solution:    "قم بتكوين معالجة الأخطاء بشكل صحيح وإخفاء المعلومات الحساسة",
				CVSS:        5.0,
				References: []string{
					"https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
				},
				Location: target,
			}
		}
	}

	return nil
}

// checkAuthenticationVulnerabilities يفحص ثغرات التوثيق
func (s *AdvancedScanner) checkAuthenticationVulnerabilities(ctx context.Context, target string) *Vulnerability {
	// فحص تجاوز التوثيق
	if vuln := s.checkAuthBypass(ctx, target); vuln != nil {
		return vuln
	}

	// فحص ضعف كلمات المرور
	if vuln := s.checkWeakPasswords(ctx, target); vuln != nil {
		return vuln
	}

	// فحص تسريب معلومات التوثيق
	if vuln := s.checkAuthInfoLeak(ctx, target); vuln != nil {
		return vuln
	}

	return nil
}

// checkCacheVulnerabilities يفحص ثغرات التخزين المؤقت
func (s *AdvancedScanner) checkCacheVulnerabilities(ctx context.Context, target string) *Vulnerability {
	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// فحص Cache-Control
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl == "" {
		return &Vulnerability{
			Type:        "Cache",
			Severity:    SeverityLow,
			Description: "لم يتم تعيين Cache-Control",
			Evidence:    "Header Cache-Control غير موجود",
			Solution:    "قم بتعيين Cache-Control بشكل صحيح لمنع التخزين المؤقت غير المرغوب فيه",
			CVSS:        3.0,
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses",
			},
			Location: target,
		}
	}

	return nil
}

// Helper functions
func (s *AdvancedScanner) createTestJWT(alg string) string {
	// TODO: تنفيذ إنشاء JWT للاختبار
	return ""
}

func (s *AdvancedScanner) checkIDOR(ctx context.Context, endpoint string) *Vulnerability {
	// TODO: تنفيذ فحص IDOR
	return nil
}

func (s *AdvancedScanner) checkMassAssignment(ctx context.Context, endpoint string) *Vulnerability {
	// TODO: تنفيذ فحص Mass Assignment
	return nil
}

func (s *AdvancedScanner) checkRateLimiting(ctx context.Context, endpoint string) *Vulnerability {
	// TODO: تنفيذ فحص Rate Limiting
	return nil
}

func (s *AdvancedScanner) checkAuthBypass(ctx context.Context, target string) *Vulnerability {
	// TODO: تنفيذ فحص تجاوز التوثيق
	return nil
}

func (s *AdvancedScanner) checkWeakPasswords(ctx context.Context, target string) *Vulnerability {
	// TODO: تنفيذ فحص ضعف كلمات المرور
	return nil
}

func (s *AdvancedScanner) checkAuthInfoLeak(ctx context.Context, target string) *Vulnerability {
	// TODO: تنفيذ فحص تسريب معلومات التوثيق
	return nil
}

func (s *AdvancedScanner) createWAFVulnerability(wafInfo *WAFInfo) *Vulnerability {
	return &Vulnerability{
		Type:        "WAF",
		Severity:    SeverityInfo,
		Description: fmt.Sprintf("تم اكتشاف WAF: %s", wafInfo.Name),
		Evidence:    fmt.Sprintf("نوع WAF: %s, الإصدار: %s", wafInfo.Type, wafInfo.Version),
		Solution:    "تأكد من تكوين WAF بشكل صحيح وتحديثه بانتظام",
		CVSS:        0.0,
		References: []string{
			"https://owasp.org/www-project-web-application-firewall/",
		},
	}
}

func (s *AdvancedScanner) discoverAPIEndpoints(ctx context.Context, target string) []string {
	// TODO: تنفيذ اكتشاف نقاط نهاية API
	return nil
} 