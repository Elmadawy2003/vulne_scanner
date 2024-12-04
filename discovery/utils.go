package discovery

import (
	"net/url"
	"strings"
	"regexp"
	"time"
	"net/http"
	"encoding/json"
	"net"
)

// RemoveDuplicates يزيل التكرار من القائمة
func RemoveDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// NormalizeURL يقوم بتنسيق الرابط
func NormalizeURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	// إزالة المعلمات غير المهمة
	cleanQuery := url.Values{}
	for key, values := range parsedURL.Query() {
		// تجاهل المعلمات المؤقتة مثل التوكن والجلسة
		if !isTemporaryParam(key) {
			cleanQuery[key] = values
		}
	}

	parsedURL.RawQuery = cleanQuery.Encode()
	return parsedURL.String(), nil
}

// isTemporaryParam يتحقق مما إذا كان المعلم مؤقتًا
func isTemporaryParam(param string) bool {
	temporaryParams := []string{
		"token", "session", "timestamp", "t",
		"utm_source", "utm_medium", "utm_campaign",
	}
	param = strings.ToLower(param)
	for _, temp := range temporaryParams {
		if strings.Contains(param, temp) {
			return true
		}
	}
	return false
}

// ValidateTarget يتحقق من صحة الهدف
func ValidateTarget(target string) bool {
	// تحقق من أن الهدف نطاق صالح
	return !strings.Contains(target, "..") &&
		!strings.Contains(target, "//") &&
		len(target) > 0
}

// ExtractDomain يستخرج النطاق الرئيسي من الرابط
func ExtractDomain(urlStr string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	
	parts := strings.Split(parsedURL.Hostname(), ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], "."), nil
	}
	return parsedURL.Hostname(), nil
}

// FilterURLsByExtension يصفي الروابط حسب الامتداد
func FilterURLsByExtension(urls []string, allowedExts []string) []string {
	if len(allowedExts) == 0 {
		return urls
	}

	filtered := []string{}
	for _, u := range urls {
		for _, ext := range allowedExts {
			if strings.HasSuffix(strings.ToLower(u), "."+strings.ToLower(ext)) {
				filtered = append(filtered, u)
				break
			}
		}
	}
	return filtered
}

// تحليل محتوى JavaScript
func ExtractURLsFromJS(content string) []string {
	var urls []string
	// استخدام تعبيرات منتظمة للعثور على الروابط في JavaScript
	urlRegex := regexp.MustCompile(`(?i)(?:(?:https?|ftp):\/\/|www\.|ftp\.)(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#\/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[A-Z0-9+&@#\/%=~_|$])`)
	matches := urlRegex.FindAllString(content, -1)
	return matches
}

// فحص حالة الرابط
func CheckURLStatus(url string, timeout time.Duration) (int, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	
	return resp.StatusCode, nil
}

// تصفية النطاقات الفرعية حسب الحالة
func FilterSubdomainsByStatus(subdomains []string, timeout time.Duration) []string {
	var validSubdomains []string
	for _, subdomain := range subdomains {
		if status, err := CheckURLStatus(subdomain, timeout); err == nil && status < 500 {
			validSubdomains = append(validSubdomains, subdomain)
		}
	}
	return validSubdomains
}

// تحليل محتوى JSON للبحث عن الروابط
func ExtractURLsFromJSON(content string) []string {
	var links []string
	var data interface{}

	if err := json.Unmarshal([]byte(content), &data); err == nil {
		extractURLsFromInterface(data, &links)
	}

	return RemoveDuplicates(links)
}

// استخراج الروابط من أي نوع بيانات
func extractURLsFromInterface(data interface{}, links *[]string) {
	switch v := data.(type) {
	case string:
		if isValidURL(v) {
			*links = append(*links, v)
		}
	case []interface{}:
		for _, item := range v {
			extractURLsFromInterface(item, links)
		}
	case map[string]interface{}:
		for _, value := range v {
			extractURLsFromInterface(value, links)
		}
	}
}

// التحقق من صحة عنوان IP
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// تحويل النطاق إلى IP
func ResolveHostToIP(host string) ([]string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}
	return ipStrings, nil
}

// فحص حالة النطاق
func CheckDomainStatus(domain string) (bool, error) {
	_, err := net.LookupNS(domain)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
