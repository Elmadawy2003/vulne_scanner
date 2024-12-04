package scanning

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"vulne_scanner/logs"
)

// WAFBypass مسؤول عن تجاوز جدران الحماية
type WAFBypass struct {
	client    *http.Client
	userAgent string
	headers   map[string]string
}

// NewWAFBypass ينشئ نسخة جديدة من WAFBypass
func NewWAFBypass() *WAFBypass {
	return &WAFBypass{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		headers: make(map[string]string),
	}
}

// Setup يقوم بإعداد تقنيات تجاوز جدار الحماية
func (wb *WAFBypass) Setup(target string) error {
	// اكتشاف نوع جدار الحماية
	wafType, err := wb.detectWAF(target)
	if err != nil {
		return err
	}

	// تكوين الترويسات المناسبة
	wb.configureBypass(wafType)
	return nil
}

// detectWAF يكتشف نوع جدار الحماية
func (wb *WAFBypass) detectWAF(target string) (string, error) {
	resp, err := wb.client.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// فحص الترويسات للكشف عن جدار الحماية
	headers := resp.Header
	if headers.Get("X-WAF") != "" {
		return headers.Get("X-WAF"), nil
	}

	// فحص العلامات المميزة لجدران الحماية المعروفة
	switch {
	case headers.Get("Server") == "cloudflare":
		return "Cloudflare", nil
	case headers.Get("X-Powered-By") == "ASP.NET":
		return "ASP.NET", nil
	case strings.Contains(headers.Get("Server"), "nginx"):
		return "Nginx", nil
	default:
		return "Unknown", nil
	}
}

// configureBypass يكون تقنيات التجاوز حسب نوع جدار الحماية
func (wb *WAFBypass) configureBypass(wafType string) {
	switch wafType {
	case "Cloudflare":
		wb.setupCloudflareBypass()
	case "ASP.NET":
		wb.setupASPNETBypass()
	case "Nginx":
		wb.setupNginxBypass()
	default:
		wb.setupGenericBypass()
	}
}

// setupCloudflareBypass يكون تقنيات تجاوز Cloudflare
func (wb *WAFBypass) setupCloudflareBypass() {
	wb.headers["CF-Connecting-IP"] = "127.0.0.1"
	wb.headers["X-Forwarded-For"] = "127.0.0.1"
	wb.headers["X-Real-IP"] = "127.0.0.1"
	wb.userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

// setupASPNETBypass يكون تقنيات تجاوز ASP.NET
func (wb *WAFBypass) setupASPNETBypass() {
	wb.headers["X-Original-URL"] = "/"
	wb.headers["X-Rewrite-URL"] = "/"
}

// setupNginxBypass يكون تقنيات تجاوز Nginx
func (wb *WAFBypass) setupNginxBypass() {
	wb.headers["X-Original-URI"] = "/"
	wb.headers["X-Forwarded-Host"] = "localhost"
}

// setupGenericBypass يكون تقنيات تجاوز عامة
func (wb *WAFBypass) setupGenericBypass() {
	wb.headers["Accept-Language"] = "en-US,en;q=0.9"
	wb.headers["Accept-Encoding"] = "gzip, deflate"
	wb.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	wb.userAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
}

// GetHeaders يعيد الترويسات المكونة
func (wb *WAFBypass) GetHeaders() map[string]string {
	return wb.headers
}

// GetUserAgent يعيد User-Agent المكون
func (wb *WAFBypass) GetUserAgent() string {
	return wb.userAgent
}

// MakeRequest ينفذ طلب HTTP مع تقنيات التجاوز
func (wb *WAFBypass) MakeRequest(method, url string, body string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	// إضافة الترويسات
	for key, value := range wb.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("User-Agent", wb.userAgent)

	// تنفيذ الطلب
	resp, err := wb.client.Do(req)
	if err != nil {
		return nil, err
	}

	// التحقق من نجاح التجاوز
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		logs.LogWarning(fmt.Sprintf("فشل في تجاوز جدار الحماية: %d", resp.StatusCode))
	}

	return resp, nil
}
