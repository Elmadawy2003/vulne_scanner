package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"net/http"
	"encoding/json"
	"regexp"
	"bufio"
	"net/url"

	"vulne_scanner/logs"
	"github.com/miekg/dns"
)

// SubdomainFinder مسؤول عن البحث عن النطاقات الفرعية
type SubdomainFinder struct {
	target     string
	concurrent int
	progress   float64
	mu         sync.Mutex
	stop       chan struct{}
	useWordlist    bool
	useCertificate bool
	useDNS         bool
	useArchive     bool
	customWordlist string
}

// NewSubdomainFinder ينشئ نسخة جديدة من SubdomainFinder
func NewSubdomainFinder(target string, concurrent int) *SubdomainFinder {
	return &SubdomainFinder{
		target:     target,
		concurrent: concurrent,
		stop:       make(chan struct{}),
	}
}

// Find يبدأ البحث عن النطاقات الفرعية
func (sf *SubdomainFinder) Find(ctx context.Context) ([]string, error) {
	var allResults []string
	var wg sync.WaitGroup
	resultsChan := make(chan []string, 4)

	// البحث باستخدام قائمة الكلمات
	if sf.useWordlist {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if results, err := sf.findByWordlist(ctx); err == nil {
				resultsChan <- results
			}
		}()
	}

	// البحث في شهادات SSL
	if sf.useCertificate {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if results, err := sf.findByCertificates(ctx); err == nil {
				resultsChan <- results
			}
		}()
	}

	// البحث في سجلات DNS
	if sf.useDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if results, err := sf.findByDNS(ctx); err == nil {
				resultsChan <- results
			}
		}()
	}

	// البحث في أرشيف الإنترنت
	if sf.useArchive {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if results, err := sf.findByArchive(ctx); err == nil {
				resultsChan <- results
			}
		}()
	}

	// جمع النتائج
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// تجميع كل النتائج
	for results := range resultsChan {
		allResults = append(allResults, results...)
	}

	return RemoveDuplicates(allResults), nil
}

// البحث في شهادات SSL
func (sf *SubdomainFinder) findByCertificates(ctx context.Context) ([]string, error) {
	var results []string
	var mu sync.Mutex

	// استخدام عدة مصادر للشهادات
	sources := []struct {
		name     string
		endpoint string
	}{
		{"crt.sh", "https://crt.sh/?q=%.%s&output=json"},
		{"censys", "https://censys.io/api/v1/search/certificates"},
		{"certspotter", "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true"},
	}

	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)
		go func(src struct {
			name     string
			endpoint string
		}) {
			defer wg.Done()

			subdomains, err := sf.fetchCertificateData(ctx, src.endpoint, src.name)
			if err != nil {
				logs.LogError(err, fmt.Sprintf("خطأ في جلب البيانات من %s", src.name))
				return
			}

			mu.Lock()
			results = append(results, subdomains...)
			mu.Unlock()
		}(source)
	}

	wg.Wait()
	return RemoveDuplicates(results), nil
}

// دالة مساعدة لجلب بيانات الشهادات
func (sf *SubdomainFinder) fetchCertificateData(ctx context.Context, endpoint, source string) ([]string, error) {
	var results []string

	// إنشاء طلب HTTP
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	url := fmt.Sprintf(endpoint, sf.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// إضافة ترويسات مخصصة حسب المصدر
	switch source {
	case "censys":
		req.Header.Set("Authorization", "Bearer YOUR_CENSYS_API_TOKEN")
	case "certspotter":
		req.Header.Set("Authorization", "Bearer YOUR_CERTSPOTTER_API_TOKEN")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// تحليل الاستجابة حسب المصدر
	switch source {
	case "crt.sh":
		var entries []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			results = append(results, strings.Split(entry.NameValue, "\n")...)
		}

	case "censys":
		// تحليل استجابة Censys
		var censysResp struct {
			Results []struct {
				Names []string `json:"names"`
			} `json:"results"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&censysResp); err != nil {
			return nil, err
		}
		for _, result := range censysResp.Results {
			results = append(results, result.Names...)
		}

	case "certspotter":
		// تحليل استجابة Certspotter
		var certspotterResp []struct {
			DNSNames []string `json:"dns_names"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&certspotterResp); err != nil {
			return nil, err
		}
		for _, cert := range certspotterResp {
			results = append(results, cert.DNSNames...)
		}
	}

	return results, nil
}

// البحث في سجلات DNS
func (sf *SubdomainFinder) findByDNS(ctx context.Context) ([]string, error) {
	var results []string
	var mu sync.Mutex

	// قائمة خوادم DNS العامة
	dnsServers := []string{
		"8.8.8.8:53",        // Google
		"1.1.1.1:53",        // Cloudflare
		"9.9.9.9:53",        // Quad9
		"208.67.222.222:53", // OpenDNS
	}

	// أنواع سجلات DNS للبحث
	recordTypes := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeMX,
		dns.TypeNS,
		dns.TypeTXT,
	}

	var wg sync.WaitGroup
	for _, server := range dnsServers {
		for _, recordType := range recordTypes {
			wg.Add(1)
			go func(server string, recordType uint16) {
				defer wg.Done()

				// إنشاء عميل DNS
				c := &dns.Client{
					Timeout: 5 * time.Second,
				}

				// إنشاء رسالة DNS
				m := &dns.Msg{}
				m.SetQuestion(dns.Fqdn(sf.target), recordType)
				m.RecursionDesired = true

				// إرسال الاستعلام
				r, _, err := c.Exchange(m, server)
				if err != nil {
					logs.LogError(err, fmt.Sprintf("خطأ في استعلام DNS من %s", server))
					return
				}

				// تحليل الاستجابة
				subdomains := sf.parseDNSResponse(r)
				mu.Lock()
				results = append(results, subdomains...)
				mu.Unlock()
			}(server, recordType)
		}
	}

	wg.Wait()
	return RemoveDuplicates(results), nil
}

// دالة مساعدة لتحليل استجابة DNS
func (sf *SubdomainFinder) parseDNSResponse(r *dns.Msg) []string {
	var results []string
	for _, answer := range r.Answer {
		switch record := answer.(type) {
		case *dns.A:
			results = append(results, record.Hdr.Name)
		case *dns.AAAA:
			results = append(results, record.Hdr.Name)
		case *dns.CNAME:
			results = append(results, record.Hdr.Name, record.Target)
		case *dns.MX:
			results = append(results, record.Hdr.Name, record.Mx)
		case *dns.NS:
			results = append(results, record.Hdr.Name, record.Ns)
		case *dns.TXT:
			results = append(results, record.Hdr.Name)
			// البحث عن النطاقات الفرعية في سجلات TXT
			for _, txt := range record.Txt {
				if subdomains := sf.extractSubdomainsFromText(txt); len(subdomains) > 0 {
					results = append(results, subdomains...)
				}
			}
		}
	}
	return results
}

// استخراج النطاقات الفرعية من النص
func (sf *SubdomainFinder) extractSubdomainsFromText(text string) []string {
	var results []string
	// تعبير منتظم للبحث ��ن النطاقات الفرعية
	pattern := fmt.Sprintf(`[a-zA-Z0-9-]+\.%s`, regexp.QuoteMeta(sf.target))
	re := regexp.MustCompile(pattern)
	matches := re.FindAllString(text, -1)
	return matches
}

// البحث في أرشيف الإنترنت
func (sf *SubdomainFinder) findByArchive(ctx context.Context) ([]string, error) {
	var results []string
	var mu sync.Mutex

	// مصادر الأرشيف
	sources := []struct {
		name     string
		endpoint string
	}{
		{"wayback", "http://web.archive.org/cdx/search/cdx?url=*.%s&output=json&collapse=urlkey"},
		{"commonCrawl", "http://index.commoncrawl.org/CC-MAIN-2021-31-index?url=*.%s&output=json"},
		{"alienvault", "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"},
	}

	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)
		go func(src struct {
			name     string
			endpoint string
		}) {
			defer wg.Done()

			subdomains, err := sf.fetchArchiveData(ctx, src.endpoint, src.name)
			if err != nil {
				logs.LogError(err, fmt.Sprintf("خطأ في جلب البيانات من %s", src.name))
				return
			}

			mu.Lock()
			results = append(results, subdomains...)
			mu.Unlock()
		}(source)
	}

	wg.Wait()
	return RemoveDuplicates(results), nil
}

// دالة مساعدة لجلب بيانات الأرشيف
func (sf *SubdomainFinder) fetchArchiveData(ctx context.Context, endpoint, source string) ([]string, error) {
	var results []string

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	url := fmt.Sprintf(endpoint, sf.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// إضافة ترويسات مخصصة حسب المصدر
	switch source {
	case "alienvault":
		req.Header.Set("X-OTX-API-KEY", "YOUR_ALIENVAULT_API_KEY")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// تحليل الاستجابة حسب المصدر
	switch source {
	case "wayback":
		var entries [][]string
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			return nil, err
		}
		for _, entry := range entries[1:] { // تجاهل الصف الأول (العناوين)
			if u, err := url.Parse(entry[2]); err == nil {
				results = append(results, u.Hostname())
			}
		}

	case "commonCrawl":
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			var entry struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
				if u, err := url.Parse(entry.URL); err == nil {
					results = append(results, u.Hostname())
				}
			}
		}

	case "alienvault":
		var alienvaultResp struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&alienvaultResp); err != nil {
			return nil, err
		}
		for _, record := range alienvaultResp.PassiveDNS {
			results = append(results, record.Hostname)
		}
	}

	return results, nil
}

// isValidSubdomain يتحقق من صحة النطاق الفرعي
func (sf *SubdomainFinder) isValidSubdomain(subdomain string) bool {
	_, err := net.LookupHost(subdomain)
	return err == nil
}

// findByWordlist يبحث عن النطاقات الفرعية باستخدام قائمة الكلمات
func (sf *SubdomainFinder) findByWordlist(ctx context.Context) ([]string, error) {
	var results []string
	var mu sync.Mutex
	wordlist := sf.loadWordlist()
	total := len(wordlist)
	
	// إنشاء قناة للكلمات
	wordChan := make(chan string, sf.concurrent)
	
	// إنشاء مجموعة عمل
	var wg sync.WaitGroup
	
	// بدء العمال
	for i := 0; i < sf.concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordChan {
				select {
				case <-ctx.Done():
					return
				case <-sf.stop:
					return
				default:
					// تجربة أنماط مختلفة من النطاقات الفرعية
					patterns := []string{
						"%s.%s",           // subdomain.example.com
						"%s-%s",           // sub-example.com
						"%s.%s.%s",        // sub.example.com
						"www.%s.%s",       // www.sub.example.com
						"%s.dev.%s",       // sub.dev.example.com
						"%s.staging.%s",   // sub.staging.example.com
						"%s.test.%s",      // sub.test.example.com
					}

					for _, pattern := range patterns {
						subdomain := fmt.Sprintf(pattern, word, sf.target)
						if sf.isValidSubdomain(subdomain) {
							mu.Lock()
							results = append(results, subdomain)
							mu.Unlock()
							logs.LogWarning(fmt.Sprintf("تم اكتشاف نطاق فرعي: %s", subdomain))
						}
					}
					
					sf.mu.Lock()
					sf.progress = (float64(len(results)) / float64(total)) * 100
					sf.mu.Unlock()
				}
			}
		}()
	}

	// إرسال الكلمات للمعالجة
	go func() {
		for _, word := range wordlist {
			select {
			case <-ctx.Done():
				close(wordChan)
				return
			case <-sf.stop:
				close(wordChan)
				return
			default:
				wordChan <- word
			}
		}
		close(wordChan)
	}()

	wg.Wait()
	return results, nil
}

// تحسين دالة loadWordlist
func (sf *SubdomainFinder) loadWordlist() []string {
	if sf.customWordlist != "" {
		// قراءة من ملف مخصص
		content, err := os.ReadFile(sf.customWordlist)
		if err == nil {
			return strings.Split(strings.TrimSpace(string(content)), "\n")
		}
	}

	// قائمة افتراضية موسعة
	return []string{
		// النطاقات الفرعية الشائعة
		"www", "mail", "ftp", "admin", "blog", "dev", "test", "stage", "api",
		"cdn", "shop", "store", "app", "mobile", "m", "secure", "vpn", "ns1",
		"ns2", "smtp", "webmail", "portal", "support", "help", "kb", "faq",

		// النطاقات الفرعية التقنية
		"jenkins", "gitlab", "git", "svn", "jira", "confluence", "wiki",
		"sonar", "nexus", "docker", "registry", "kubernetes", "k8s",
		"prometheus", "grafana", "kibana", "elastic", "redis", "mysql",
		"postgres", "mongo", "db", "database", "cache", "queue",

		// النطاقات الفرعية الأمنية
		"security", "auth", "sso", "login", "oauth", "idp", "ldap",
		"admin-panel", "phpmyadmin", "webadmin", "adminer", "wp-admin",

		// النطاقات الفرعية للتطوير
		"staging", "dev-api", "test-api", "uat", "qa", "demo", "beta",
		"alpha", "development", "testing", "integration", "preview",
	}
}

// GetProgress يعيد نسبة تقدم البحث
func (sf *SubdomainFinder) GetProgress() float64 {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	return sf.progress
}

// Stop يوقف عملية البحث
func (sf *SubdomainFinder) Stop() {
	close(sf.stop)
}
