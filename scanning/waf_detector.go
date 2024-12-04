package scanning

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// WAFInfo معلومات نظام WAF
type WAFInfo struct {
	Name    string
	Type    string
	Version string
	Rules   []string
}

// WAFDetector كاشف أنظمة WAF
type WAFDetector struct {
	signatures map[string]WAFSignature
	client     *http.Client
}

// WAFSignature توقيع نظام WAF
type WAFSignature struct {
	Name       string
	Headers    map[string]string
	Cookies    []string
	BodyRegex  []string
	StatusCode []int
}

// NewWAFDetector ينشئ كاشف WAF جديد
func NewWAFDetector() *WAFDetector {
	return &WAFDetector{
		signatures: loadWAFSignatures(),
		client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// DetectWAF يكتشف وجود WAF
func (w *WAFDetector) DetectWAF(ctx context.Context, target string) *WAFInfo {
	// إرسال طلب عادي
	normalResp, err := w.sendRequest(ctx, target, false)
	if err != nil {
		return nil
	}
	defer normalResp.Body.Close()

	// إرسال طلب مشبوه
	maliciousResp, err := w.sendRequest(ctx, target, true)
	if err != nil {
		return nil
	}
	defer maliciousResp.Body.Close()

	// تحليل الاستجابات
	for name, sig := range w.signatures {
		if w.matchSignature(normalResp, maliciousResp, sig) {
			return &WAFInfo{
				Name:    name,
				Type:    w.determineWAFType(normalResp, maliciousResp),
				Version: w.detectVersion(normalResp, maliciousResp),
				Rules:   w.detectRules(normalResp, maliciousResp),
			}
		}
	}

	return nil
}

// sendRequest يرسل طلب HTTP
func (w *WAFDetector) sendRequest(ctx context.Context, target string, malicious bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}

	if malicious {
		w.addMaliciousParameters(req)
	}

	return w.client.Do(req)
}

// addMaliciousParameters يضيف معاملات مشبوهة للطلب
func (w *WAFDetector) addMaliciousParameters(req *http.Request) {
	// إضافة معاملات SQL Injection
	q := req.URL.Query()
	q.Add("id", "1' OR '1'='1")
	req.URL.RawQuery = q.Encode()

	// إضافة ترويسات مشبوهة
	req.Header.Set("User-Agent", "sqlmap/1.4.7")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
}

// matchSignature يطابق توقيع WAF
func (w *WAFDetector) matchSignature(normalResp, maliciousResp *http.Response, sig WAFSignature) bool {
	// فحص الترويسات
	for header, value := range sig.Headers {
		if strings.Contains(maliciousResp.Header.Get(header), value) {
			return true
		}
	}

	// فحص الكوكيز
	for _, cookie := range sig.Cookies {
		for _, c := range maliciousResp.Cookies() {
			if strings.Contains(c.Name, cookie) || strings.Contains(c.Value, cookie) {
				return true
			}
		}
	}

	// فحص محتوى الاستجابة
	body, err := io.ReadAll(maliciousResp.Body)
	if err == nil {
		bodyStr := string(body)
		for _, regex := range sig.BodyRegex {
			if match, _ := regexp.MatchString(regex, bodyStr); match {
				return true
			}
		}
	}

	// فحص رمز الحالة
	for _, code := range sig.StatusCode {
		if maliciousResp.StatusCode == code {
			return true
		}
	}

	return false
}

// determineWAFType يحدد نوع WAF
func (w *WAFDetector) determineWAFType(normalResp, maliciousResp *http.Response) string {
	// فحص الترويسات الشائعة
	if server := maliciousResp.Header.Get("Server"); server != "" {
		if strings.Contains(strings.ToLower(server), "cloudflare") {
			return "CloudFlare WAF"
		}
		if strings.Contains(strings.ToLower(server), "nginx") {
			return "NGINX WAF"
		}
		if strings.Contains(strings.ToLower(server), "apache") {
			return "ModSecurity"
		}
	}

	// فحص الكوكيز
	for _, cookie := range maliciousResp.Cookies() {
		if strings.Contains(strings.ToLower(cookie.Name), "waf") {
			return fmt.Sprintf("Custom WAF (%s)", cookie.Name)
		}
	}

	return "Unknown WAF"
}

// detectVersion يكتشف إصدار WAF
func (w *WAFDetector) detectVersion(normalResp, maliciousResp *http.Response) string {
	// محاولة استخراج الإصدار من الترويسات
	if server := maliciousResp.Header.Get("Server"); server != "" {
		if version := extractVersion(server); version != "" {
			return version
		}
	}

	// محاولة استخراج الإصدار من الكوكيز
	for _, cookie := range maliciousResp.Cookies() {
		if version := extractVersion(cookie.Value); version != "" {
			return version
		}
	}

	return "Unknown"
}

// detectRules يكتشف قواعد WAF
func (w *WAFDetector) detectRules(normalResp, maliciousResp *http.Response) []string {
	var rules []string

	// فحص رسائل الخطأ
	body, err := io.ReadAll(maliciousResp.Body)
	if err == nil {
		bodyStr := string(body)
		
		// البحث عن أنماط قواعد WAF
		patterns := []struct {
			regex string
			rule  string
		}{
			{`(?i)sql\s*injection`, "SQL Injection Protection"},
			{`(?i)xss`, "XSS Protection"},
			{`(?i)remote\s*file\s*inclusion`, "RFI Protection"},
			{`(?i)local\s*file\s*inclusion`, "LFI Protection"},
			{`(?i)directory\s*traversal`, "Path Traversal Protection"},
			{`(?i)remote\s*code\s*execution`, "RCE Protection"},
			{`(?i)command\s*injection`, "Command Injection Protection"},
		}

		for _, pattern := range patterns {
			if match, _ := regexp.MatchString(pattern.regex, bodyStr); match {
				rules = append(rules, pattern.rule)
			}
		}
	}

	// فحص الترويسات الأمنية
	securityHeaders := []string{
		"X-XSS-Protection",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Content-Security-Policy",
		"Strict-Transport-Security",
	}

	for _, header := range securityHeaders {
		if value := maliciousResp.Header.Get(header); value != "" {
			rules = append(rules, fmt.Sprintf("%s: %s", header, value))
		}
	}

	return rules
}

// loadWAFSignatures يحمل توقيعات WAF المعروفة
func loadWAFSignatures() map[string]WAFSignature {
	return map[string]WAFSignature{
		"Cloudflare": {
			Name: "Cloudflare WAF",
			Headers: map[string]string{
				"Server":                    "cloudflare",
				"CF-RAY":                   "",
				"CF-Cache-Status":          "",
				"Expect-CT":                "",
				"X-Content-Type-Options":   "nosniff",
				"X-Frame-Options":          "SAMEORIGIN",
				"X-XSS-Protection":         "1",
			},
			Cookies: []string{
				"__cfduid",
				"cf_clearance",
			},
			BodyRegex: []string{
				`(?i)cloudflare`,
				`(?i)ray id:`,
			},
			StatusCode: []int{403, 503},
		},
		"ModSecurity": {
			Name: "ModSecurity WAF",
			Headers: map[string]string{
				"Server": "ModSecurity",
			},
			BodyRegex: []string{
				`(?i)mod_security`,
				`(?i)blocked by mod_security`,
			},
			StatusCode: []int{403, 406},
		},
		"NGINX WAF": {
			Name: "NGINX WAF",
			Headers: map[string]string{
				"Server": "nginx",
			},
			BodyRegex: []string{
				`(?i)nginx`,
				`(?i)blocked by nginx`,
			},
			StatusCode: []int{403, 406},
		},
		"AWS WAF": {
			Name: "AWS WAF",
			Headers: map[string]string{
				"X-AMZ-CF-ID": "",
				"X-AMZ-ID-2": "",
			},
			BodyRegex: []string{
				`(?i)aws`,
				`(?i)amazon`,
			},
			StatusCode: []int{403, 405},
		},
		"F5 BIG-IP ASM": {
			Name: "F5 BIG-IP ASM",
			Headers: map[string]string{
				"Server": "BigIP",
			},
			Cookies: []string{
				"TS",
				"BIGipServer",
			},
			BodyRegex: []string{
				`(?i)the requested url was rejected`,
				`(?i)please consult with your administrator`,
			},
			StatusCode: []int{403, 501},
		},
	}
}

// extractVersion يستخرج رقم الإصدار من النص
func extractVersion(text string) string {
	versionRegex := regexp.MustCompile(`\d+(\.\d+)*`)
	if match := versionRegex.FindString(text); match != "" {
		return match
	}
	return ""
} 