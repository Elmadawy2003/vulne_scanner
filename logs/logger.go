package logs

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

var (
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
)

// Initialize يقوم بتهيئة نظام السجلات
func Initialize(debug bool) error {
	// إنشاء مجلد السجلات إذا لم يكن موجوداً
	if err := os.MkdirAll("logs", 0755); err != nil {
		return fmt.Errorf("فشل في إنشاء مجلد السجلات: %v", err)
	}

	// إنشاء ملف السجلات
	logFile := filepath.Join("logs", fmt.Sprintf("scanner_%s.log", time.Now().Format("2006-01-02")))
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("فشل في فتح ملف السجلات: %v", err)
	}

	// تهيئة المسجلات
	flags := log.Ldate | log.Ltime | log.Lmicroseconds
	infoLogger = log.New(file, "معلومات: ", flags)
	warnLogger = log.New(file, "تحذير: ", flags)
	errorLogger = log.New(file, "خطأ: ", flags)
	
	if debug {
		debugLogger = log.New(file, "تصحيح: ", flags)
	} else {
		debugLogger = log.New(os.Stderr, "تصحيح: ", flags)
	}

	return nil
}

// LogInfo تسجيل رسالة معلومات
func LogInfo(message string) {
	if infoLogger != nil {
		infoLogger.Println(message)
	}
	log.Printf("معلومات: %s\n", message)
}

// LogWarning تسجيل رسالة تحذير
func LogWarning(message string) {
	if warnLogger != nil {
		warnLogger.Println(message)
	}
	log.Printf("تحذير: %s\n", message)
}

// LogError تسجيل رسالة خطأ
func LogError(err error, message string) {
	errMsg := fmt.Sprintf("%s: %v", message, err)
	if errorLogger != nil {
		errorLogger.Println(errMsg)
	}
	log.Printf("خطأ: %s\n", errMsg)
}

// LogDebug تسجيل رسالة تصحيح
func LogDebug(message string) {
	if debugLogger != nil {
		debugLogger.Println(message)
	}
}

// LogFatal تسجيل رسالة خطأ فادح وإنهاء البرنامج
func LogFatal(err error, message string) {
	errMsg := fmt.Sprintf("%s: %v", message, err)
	if errorLogger != nil {
		errorLogger.Println(errMsg)
	}
	log.Fatalf("خطأ فادح: %s\n", errMsg)
}

// LogPanic تسجيل رسالة خطأ وإثارة panic
func LogPanic(err error, message string) {
	errMsg := fmt.Sprintf("%s: %v", message, err)
	if errorLogger != nil {
		errorLogger.Println(errMsg)
	}
	log.Panicf("خطأ: %s\n", errMsg)
}

// GetLogFilePath يعيد مسار ملف السجلات الحالي
func GetLogFilePath() string {
	return filepath.Join("logs", fmt.Sprintf("scanner_%s.log", time.Now().Format("2006-01-02")))
}

// RotateLogs تدوير ملفات السجلات القديمة
func RotateLogs(maxAge time.Duration, maxSize int64) error {
	entries, err := os.ReadDir("logs")
	if err != nil {
		return fmt.Errorf("فشل في قراءة مجلد السجلات: %v", err)
	}

	now := time.Now()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join("logs", entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// حذف الملفات القديمة
		if now.Sub(info.ModTime()) > maxAge {
			os.Remove(path)
			continue
		}

		// حذف الملفات الكبيرة
		if info.Size() > maxSize {
			os.Remove(path)
		}
	}

	return nil
} 