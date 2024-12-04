package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"vulne_scanner/logs"
	"github.com/PuerkitoBio/goquery"
	"bufio"
)

// URLCollector مسؤول عن جمع الروابط
type URLCollector struct {
	baseURL   string
	maxDepth  int
	visited   map[string]bool
	progress  float64
	mu        sync.Mutex
	stop      chan struct{}
	parseJS       bool
	parseComments bool
	parseRobots   bool
	client        *http.Client
	headers       map[string]string
}

// NewURLCollector ينشئ نسخة جديدة من URLCollector
func NewURLCollector(baseURL string, maxDepth int) *URLCollector {
	return &URLCollector{
		baseURL:  baseURL,
		maxDepth: maxDepth,
		visited:  make(map[string]bool),
		stop:     make(chan struct{}),
	}
}

// Collect يبدأ عملية جمع الروابط
func (uc *URLCollector) Collect(ctx context.Context) ([]string, error) {
	var results []string
	queue := []string{uc.baseURL}
	depth := make(map[string]int)
	depth[uc.baseURL] = 0

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case <-uc.stop:
			return results, nil
		default:
			current := queue[0]
			queue = queue[1:]

			if depth[current] > uc.maxDepth {
				continue
			}

			if uc.visited[current] {
				continue
			}

			uc.mu.Lock()
			uc.visited[current] = true
			uc.mu.Unlock()

			links, err := uc.fetchLinks(current)
			if err != nil {
				logs.LogError(err, fmt.Sprintf("خطأ في جمع الروابط من %s", current))
				continue
			}

			results = append(results, current)
			logs.LogWarning(fmt.Sprintf("تم اكتشاف رابط: %s", current))

			for _, link := range links {
				if !uc.visited[link] {
					queue = append(queue, link)
					depth[link] = depth[current] + 1
				}
			}

			uc.updateProgress(len(results))
		}
	}

	return results, nil
}

// fetchLinks يجمع الروابط من صفحة معينة
func (uc *URLCollector) fetchLinks(pageURL string) ([]string, error) {
	var allLinks []string

	// إنشاء طلب HTTP مع الترويسات المخصصة
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return nil, err
	}

	// إضافة الترويسات
	for key, value := range uc.headers {
		req.Header.Set(key, value)
	}

	resp, err := uc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// استخدام goquery لتحليل HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	// جمع الروابط من الـ HTML
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			if normalized, err := NormalizeURL(href); err == nil {
				allLinks = append(allLinks, normalized)
			}
		}
	})

	// جمع الروابط من ملفات JavaScript
	if uc.parseJS {
		doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
			if src, exists := s.Attr("src"); exists {
				if jsLinks, err := uc.parseJavaScriptFile(src); err == nil {
					allLinks = append(allLinks, jsLinks...)
				}
			}
		})
	}

	// فحص التعليقات HTML
	if uc.parseComments {
		if commentLinks := uc.parseHTMLComments(doc); len(commentLinks) > 0 {
			allLinks = append(allLinks, commentLinks...)
		}
	}

	// فحص ملف robots.txt
	if uc.parseRobots {
		if robotsLinks, err := uc.parseRobotsFile(pageURL); err == nil {
			allLinks = append(allLinks, robotsLinks...)
		}
	}

	return RemoveDuplicates(allLinks), nil
}

// تحليل ملفات JavaScript
func (uc *URLCollector) parseJavaScriptFile(jsURL string) ([]string, error) {
	var links []string

	// تحميل محتوى JavaScript
	resp, err := uc.client.Get(jsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// البحث عن الروابط في التعليقات
	commentRegex := regexp.MustCompile(`(?s)/\*.*?\*/|//.*?\n`)
	comments := commentRegex.FindAllString(string(content), -1)
	for _, comment := range comments {
		if urls := ExtractURLsFromJS(comment); len(urls) > 0 {
			links = append(links, urls...)
		}
	}

	// البحث عن الروابط في المتغيرات
	varRegex := regexp.MustCompile(`(?:const|let|var)\s+\w+\s*=\s*['"]([^'"]+)['"]`)
	if matches := varRegex.FindAllStringSubmatch(string(content), -1); len(matches) > 0 {
		for _, match := range matches {
			if isValidURL(match[1]) {
				links = append(links, match[1])
			}
		}
	}

	// البحث عن الروابط في طلبات API
	apiRegex := regexp.MustCompile(`(?:fetch|axios\.get|\.ajax)\s*\(\s*['"]([^'"]+)['"]`)
	if matches := apiRegex.FindAllStringSubmatch(string(content), -1); len(matches) > 0 {
		for _, match := range matches {
			if isValidURL(match[1]) {
				links = append(links, match[1])
			}
		}
	}

	return RemoveDuplicates(links), nil
}

// تحليل التعليقات
func (uc *URLCollector) parseHTMLComments(doc *goquery.Document) []string {
	var links []string
	
	// استخراج التعليقات من HTML
	doc.Contents().Each(func(i int, s *goquery.Selection) {
		if goquery.NodeComment == s.Get(0).Type {
			comment := s.Text()
			
			// البحث عن الروابط في التعليقات
			if urls := ExtractURLsFromJS(comment); len(urls) > 0 {
				links = append(links, urls...)
			}

			// البحث عن أكواد HTML معطلة
			if doc, err := goquery.NewDocumentFromReader(strings.NewReader(comment)); err == nil {
				doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
					if href, exists := s.Attr("href"); exists {
						if normalized, err := NormalizeURL(href); err == nil {
							links = append(links, normalized)
						}
					}
				})
			}
		}
	})

	return RemoveDuplicates(links)
}

// تحليل ملف robots.txt
func (uc *URLCollector) parseRobotsFile(baseURL string) ([]string, error) {
	var links []string
	robotsURL := fmt.Sprintf("%s/robots.txt", baseURL)

	resp, err := uc.client.Get(robotsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// البحث عن المسارات المسموحة والممنوعة
		if strings.HasPrefix(line, "Allow:") || strings.HasPrefix(line, "Disallow:") {
			path := strings.TrimSpace(strings.Split(line, ":")[1])
			if path != "" && path != "/" {
				fullURL := fmt.Sprintf("%s%s", baseURL, path)
				links = append(links, fullURL)
			}
		}

		// البحث عن خرائط الموقع
		if strings.HasPrefix(line, "Sitemap:") {
			sitemapURL := strings.TrimSpace(strings.Split(line, ":")[1])
			if sitemapLinks, err := uc.parseSitemap(sitemapURL); err == nil {
				links = append(links, sitemapLinks...)
			}
		}
	}

	return RemoveDuplicates(links), scanner.Err()
}

// إضافة دالة جديدة لتحليل خرائط الموقع
func (uc *URLCollector) parseSitemap(sitemapURL string) ([]string, error) {
	var links []string

	resp, err := uc.client.Get(sitemapURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	// جمع الروابط من خريطة الموقع
	doc.Find("url > loc").Each(func(i int, s *goquery.Selection) {
		links = append(links, s.Text())
	})

	// البحث عن خرائط موقع فرعية
	doc.Find("sitemap > loc").Each(func(i int, s *goquery.Selection) {
		if subLinks, err := uc.parseSitemap(s.Text()); err == nil {
			links = append(links, subLinks...)
		}
	})

	return RemoveDuplicates(links), nil
}

// isValidURL يتحقق من صحة الرابط
func (uc *URLCollector) isValidURL(link string) bool {
	parsedURL, err := url.Parse(link)
	if err != nil {
		return false
	}

	// تحقق من أن الرابط ينتمي للنطاق المستهدف
	return strings.Contains(parsedURL.Host, uc.baseURL)
}

// updateProgress يحدث نسبة التقدم
func (uc *URLCollector) updateProgress(found int) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	// تحديث بسيط للتقدم - يمكن تحسينه
	uc.progress = float64(found) * 100 / float64(1000) // افتراض حد أقصى
}

// GetProgress يعيد نسبة تقدم العملية
func (uc *URLCollector) GetProgress() float64 {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	return uc.progress
}

// Stop يوقف عملية جمع الروابط
func (uc *URLCollector) Stop() {
	close(uc.stop)
}
