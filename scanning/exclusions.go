package scanning

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ExclusionManager مدير الروابط المستبعدة
type ExclusionManager struct {
	mu              sync.RWMutex
	excludedURLs    map[string]bool
	excludedDomains map[string]bool
	excludedPaths   map[string]bool
	excludedParams  map[string]bool
}

// NewExclusionManager ينشئ مدير جديد للروابط المستبعدة
func NewExclusionManager() *ExclusionManager {
	return &ExclusionManager{
		excludedURLs:    make(map[string]bool),
		excludedDomains: make(map[string]bool),
		excludedPaths:   make(map[string]bool),
		excludedParams:  make(map[string]bool),
	}
}

// LoadExclusionsFromFile تحميل الاستثناءات من ملف
func (em *ExclusionManager) LoadExclusionsFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("فشل في فتح ملف الاستثناءات: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// تجاهل الأسطر الفارغة والتعليقات
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// تحليل نوع الاستثناء
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("تنسيق غير صالح في السطر %d: %s", lineNum, line)
		}

		exclusionType := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if err := em.AddExclusion(exclusionType, value); err != nil {
			return fmt.Errorf("خطأ في السطر %d: %v", lineNum, err)
		}
	}

	return scanner.Err()
}

// AddExclusion إضافة استثناء جديد
func (em *ExclusionManager) AddExclusion(exclusionType, value string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	switch strings.ToLower(exclusionType) {
	case "url":
		if _, err := url.Parse(value); err != nil {
			return fmt.Errorf("رابط غير صالح: %s", value)
		}
		em.excludedURLs[value] = true

	case "domain":
		em.excludedDomains[strings.ToLower(value)] = true

	case "path":
		// تنظيف المسار
		cleanPath := filepath.Clean(value)
		em.excludedPaths[cleanPath] = true

	case "param":
		em.excludedParams[strings.ToLower(value)] = true

	default:
		return fmt.Errorf("نوع استثناء غير معروف: %s", exclusionType)
	}

	return nil
}

// RemoveExclusion إزالة استثناء
func (em *ExclusionManager) RemoveExclusion(exclusionType, value string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	switch strings.ToLower(exclusionType) {
	case "url":
		delete(em.excludedURLs, value)
	case "domain":
		delete(em.excludedDomains, strings.ToLower(value))
	case "path":
		delete(em.excludedPaths, filepath.Clean(value))
	case "param":
		delete(em.excludedParams, strings.ToLower(value))
	default:
		return fmt.Errorf("نوع استثناء غير معروف: %s", exclusionType)
	}

	return nil
}

// IsExcluded التحقق مما إذا كان الرابط مستثنى
func (em *ExclusionManager) IsExcluded(targetURL string) bool {
	em.mu.RLock()
	defer em.mu.RUnlock()

	// التحقق من الرابط الكامل
	if em.excludedURLs[targetURL] {
		return true
	}

	// تحليل الرابط
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// التحقق من النطاق
	domain := strings.ToLower(parsedURL.Hostname())
	if em.excludedDomains[domain] {
		return true
	}

	// التحقق من المسار
	cleanPath := filepath.Clean(parsedURL.Path)
	if em.excludedPaths[cleanPath] {
		return true
	}

	// التحقق من المعاملات
	query := parsedURL.Query()
	for param := range query {
		if em.excludedParams[strings.ToLower(param)] {
			return true
		}
	}

	return false
}

// IsParamExcluded التحقق مما إذا كان المعامل مستثنى
func (em *ExclusionManager) IsParamExcluded(param string) bool {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.excludedParams[strings.ToLower(param)]
}

// GetExclusions الحصول على قائمة الاستثناءات
func (em *ExclusionManager) GetExclusions() map[string][]string {
	em.mu.RLock()
	defer em.mu.RUnlock()

	exclusions := make(map[string][]string)

	// نسخ الروابط المستثناة
	urls := make([]string, 0, len(em.excludedURLs))
	for url := range em.excludedURLs {
		urls = append(urls, url)
	}
	exclusions["urls"] = urls

	// نسخ النطاقات المستثناة
	domains := make([]string, 0, len(em.excludedDomains))
	for domain := range em.excludedDomains {
		domains = append(domains, domain)
	}
	exclusions["domains"] = domains

	// نسخ المسارات المستثناة
	paths := make([]string, 0, len(em.excludedPaths))
	for path := range em.excludedPaths {
		paths = append(paths, path)
	}
	exclusions["paths"] = paths

	// نسخ المعاملات المستثناة
	params := make([]string, 0, len(em.excludedParams))
	for param := range em.excludedParams {
		params = append(params, param)
	}
	exclusions["params"] = params

	return exclusions
}

// SaveExclusionsToFile حفظ الاستثناءات إلى ملف
func (em *ExclusionManager) SaveExclusionsToFile(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("فشل في إنشاء ملف الاستثناءات: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// كتابة رأس الملف
	writer.WriteString("# ملف الاستثناءات\n")
	writer.WriteString("# التنسيق: نوع_الاستثناء: القيمة\n\n")

	// كتابة الروابط المستثناة
	for url := range em.excludedURLs {
		writer.WriteString(fmt.Sprintf("url: %s\n", url))
	}

	// كتابة النطاقات المستثناة
	for domain := range em.excludedDomains {
		writer.WriteString(fmt.Sprintf("domain: %s\n", domain))
	}

	// كتابة المسارات المستثناة
	for path := range em.excludedPaths {
		writer.WriteString(fmt.Sprintf("path: %s\n", path))
	}

	// كتابة المعاملات المستثناة
	for param := range em.excludedParams {
		writer.WriteString(fmt.Sprintf("param: %s\n", param))
	}

	return writer.Flush()
} 