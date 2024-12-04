package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vulne_scanner/logs"
)

// FileUtils مجموعة من الوظائف للتعامل مع الملفات
type FileUtils struct {
	BasePath string
}

// NewFileUtils ينشئ نسخة جديدة من FileUtils
func NewFileUtils(basePath string) *FileUtils {
	return &FileUtils{
		BasePath: basePath,
	}
}

// SaveToFile يحفظ البيانات في ملف
func (fu *FileUtils) SaveToFile(data interface{}, filename string) error {
	// إنشاء المجلد إذا لم يكن موجوداً
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("فشل في إنشاء المجلد: %v", err)
	}

	// فتح الملف للكتابة
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("فشل في إنشاء الملف: %v", err)
	}
	defer file.Close()

	// تحويل البيانات إلى JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("فشل في كتابة البيانات: %v", err)
	}

	return nil
}

// LoadFromFile يقرأ البيانات من ملف
func (fu *FileUtils) LoadFromFile(filename string, data interface{}) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("فشل في فتح الملف: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(data); err != nil {
		return fmt.Errorf("فشل في قراءة البيانات: %v", err)
	}

	return nil
}

// ReadWordlist يقرأ قائمة كلمات من ملف
func (fu *FileUtils) ReadWordlist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("فشل في فتح ملف قائمة الكلمات: %v", err)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("فشل في قراءة قائمة الكلمات: %v", err)
	}

	return words, nil
}

// CreateBackup ينشئ نسخة احتياطية م�� الملف
func (fu *FileUtils) CreateBackup(filename string) error {
	// قراءة الملف الأصلي
	source, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("فشل في فتح الملف الأصلي: %v", err)
	}
	defer source.Close()

	// إنشاء اسم ملف النسخة الاحتياطية
	backupName := fmt.Sprintf("%s.backup.%s", filename, time.Now().Format("20060102150405"))
	
	// إنشاء ملف النسخة الاحتياطية
	destination, err := os.Create(backupName)
	if err != nil {
		return fmt.Errorf("فشل في إنشاء ملف النسخة الاحتياطية: %v", err)
	}
	defer destination.Close()

	// نسخ المحتوى
	if _, err := io.Copy(destination, source); err != nil {
		return fmt.Errorf("فشل في نسخ المحتوى: %v", err)
	}

	logs.LogWarning(fmt.Sprintf("تم إنشاء نسخة احتياطية: %s", backupName))
	return nil
}

// IsFileExists يتحقق من وجود الملف
func (fu *FileUtils) IsFileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// GetFileSize يعيد حجم الملف
func (fu *FileUtils) GetFileSize(filename string) (int64, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return 0, fmt.Errorf("فشل في الحصول على معلومات الملف: %v", err)
	}
	return info.Size(), nil
}

// CleanupOldFiles يحذف الملفات القديمة
func (fu *FileUtils) CleanupOldFiles(dir string, maxAge time.Duration) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// تجاهل المجلدات
		if info.IsDir() {
			return nil
		}

		// التحقق من عمر الملف
		if time.Since(info.ModTime()) > maxAge {
			if err := os.Remove(path); err != nil {
				logs.LogError(err, fmt.Sprintf("فشل في حذف الملف القديم: %s", path))
				return err
			}
			logs.LogWarning(fmt.Sprintf("تم حذف الملف القديم: %s", path))
		}

		return nil
	})
}
