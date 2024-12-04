package utils

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vulne_scanner/logs"
)

// NetworkUtils مجموعة من الوظائف للتعامل مع الشبكة
type NetworkUtils struct {
	Timeout    time.Duration
	UserAgent  string
	MaxRetries int
}

// NewNetworkUtils ينشئ نسخة جديدة من NetworkUtils
func NewNetworkUtils() *NetworkUtils {
	return &NetworkUtils{
		Timeout:    10 * time.Second,
		UserAgent:  "VulnScanner/1.0",
		MaxRetries: 3,
	}
}

// IsHostAlive يتحقق من نشاط المضيف
func (nu *NetworkUtils) IsHostAlive(host string) bool {
	// تجربة Ping
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", host), nu.Timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// تجربة طلب HTTP
	resp, err := http.Get(fmt.Sprintf("http://%s", host))
	if err == nil {
		resp.Body.Close()
		return true
	}

	return false
}

// GetOpenPorts يكتشف المنافذ المفتوحة
func (nu *NetworkUtils) GetOpenPorts(host string, ports []int) ([]int, error) {
	var openPorts []int

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, nu.Timeout)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}

	return openPorts, nil
}

// MakeHTTPRequest ينفذ طلب HTTP مع إعادة المحاولة
func (nu *NetworkUtils) MakeHTTPRequest(ctx context.Context, urlStr string) (*http.Response, error) {
	client := &http.Client{
		Timeout: nu.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // عدم تتبع إعادة التوجيه
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", nu.UserAgent)

	var resp *http.Response
	var lastErr error

	// محاولة الطلب مع إعادة المحاولة
	for i := 0; i < nu.MaxRetries; i++ {
		resp, lastErr = client.Do(req)
		if lastErr == nil {
			return resp, nil
		}

		logs.LogWarning(fmt.Sprintf("فشلت المحاولة %d: %v", i+1, lastErr))
		time.Sleep(time.Second * time.Duration(i+1))
	}

	return nil, fmt.Errorf("فشلت جميع المحاولات: %v", lastErr)
}

// ValidateURL يتحقق من صحة الرابط
func (nu *NetworkUtils) ValidateURL(urlStr string) (string, error) {
	// إضافة البروتوكول إذا لم يكن موجوداً
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "http://" + urlStr
	}

	// تحليل الرابط
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("رابط غير صالح: %v", err)
	}

	// التحقق من وجود المضيف
	if parsedURL.Host == "" {
		return "", fmt.Errorf("المضيف غير موجود في الرابط")
	}

	return parsedURL.String(), nil
}

// GetHostInfo يجمع معلومات عن المضيف
func (nu *NetworkUtils) GetHostInfo(host string) (map[string]interface{}, error) {
	info := make(map[string]interface{})

	// البحث عن عناوين IP
	ips, err := net.LookupIP(host)
	if err == nil {
		var ipList []string
		for _, ip := range ips {
			ipList = append(ipList, ip.String())
		}
		info["ips"] = ipList
	}

	// البحث عن سجلات MX
	mxRecords, err := net.LookupMX(host)
	if err == nil {
		var mxList []string
		for _, mx := range mxRecords {
			mxList = append(mxList, mx.Host)
		}
		info["mx_records"] = mxList
	}

	// البحث عن سجلات TXT
	txtRecords, err := net.LookupTXT(host)
	if err == nil {
		info["txt_records"] = txtRecords
	}

	return info, nil
}
