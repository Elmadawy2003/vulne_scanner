package logs

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	errorLog   *log.Logger
	warningLog *log.Logger
	infoLog    *log.Logger
	debugLog   *log.Logger
	logFile    *os.File
	mu         sync.Mutex
)

// LogConfig إعدادات السجلات
type LogConfig struct {
	Level         string `json:"level"`
	MaxSize       int64  `json:"max_size"`
	MaxBackups    int    `json:"max_backups"`
	Compress      bool   `json:"compress"`
	JSONFormat    bool   `json:"json_format"`
	IncludeCaller bool   `json:"include_caller"`
	LogPath       string `json:"log_path"`
}

// InitLogger تهيئة نظام السجلات
func InitLogger(config *LogConfig) error {
	mu.Lock()
	defer mu.Unlock()

	// إنشاء مجلد السجلات إذا لم يكن موجوداً
	logDir := filepath.Dir(config.LogPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("فشل في إنشاء مجلد السجلات: %v", err)
	}

	// فتح ملف السجلات
	file, err := os.OpenFile(config.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("فشل في فتح ملف السجلات: %v", err)
	}
	logFile = file

	// إعداد الكتابة المتعددة
	multiWriter := io.MultiWriter(os.Stdout, logFile)

	// تهيئة السجلات
	flags := log.Ldate | log.Ltime
	if config.IncludeCaller {
		flags |= log.Lshortfile
	}

	errorLog = log.New(multiWriter, "خطأ\t", flags)
	warningLog = log.New(multiWriter, "تحذير\t", flags)
	infoLog = log.New(multiWriter, "معلومات\t", flags)
	
	if config.Level == "debug" {
		debugLog = log.New(multiWriter, "تصحيح\t", flags)
	}

	// بدء مراقبة حجم الملف
	go monitorFileSize(config)

	return nil
}

// LogError تسجيل خطأ
func LogError(err error, message string) {
	mu.Lock()
	defer mu.Unlock()

	if errorLog != nil {
		_, file, line, _ := runtime.Caller(1)
		errorLog.Printf("%s:%d - %s: %v", filepath.Base(file), line, message, err)
	}
}

// LogWarning تسجيل تحذير
func LogWarning(message string) {
	mu.Lock()
	defer mu.Unlock()

	if warningLog != nil {
		_, file, line, _ := runtime.Caller(1)
		warningLog.Printf("%s:%d - %s", filepath.Base(file), line, message)
	}
}

// LogInfo تسجيل معلومات
func LogInfo(message string) {
	mu.Lock()
	defer mu.Unlock()

	if infoLog != nil {
		infoLog.Println(message)
	}
}

// LogDebug تسجيل معلومات التصحيح
func LogDebug(message string) {
	mu.Lock()
	defer mu.Unlock()

	if debugLog != nil {
		_, file, line, _ := runtime.Caller(1)
		debugLog.Printf("%s:%d - %s", filepath.Base(file), line, message)
	}
}

// monitorFileSize مراقبة حجم ملف السجلات
func monitorFileSize(config *LogConfig) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := rotateLogFile(config); err != nil {
			LogError(err, "فشل في تدوير ملف السجلات")
		}
	}
}

// rotateLogFile تدوير ملف السجلات عند تجاوز الحجم
func rotateLogFile(config *LogConfig) error {
	if logFile == nil {
		return nil
	}

	info, err := logFile.Stat()
	if err != nil {
		return err
	}

	// تحويل MaxSize إلى بايت
	maxSizeBytes := config.MaxSize * 1024 * 1024 // تحويل من ميجابايت إلى بايت

	if info.Size() < maxSizeBytes {
		return nil
	}

	// إغلاق الملف الحالي
	logFile.Close()

	// إنشاء نسخة احتياطية
	backupName := fmt.Sprintf("%s.%s", config.LogPath, time.Now().Format("20060102150405"))
	if err := os.Rename(config.LogPath, backupName); err != nil {
		return err
	}

	// حذف النسخ القديمة إذا تجاوز العدد المحدد
	if err := cleanOldBackups(config); err != nil {
		return err
	}

	// إنشاء ملف جديد
	logFile, err = os.OpenFile(config.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}

	// إعادة تهيئة السجلات
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	errorLog.SetOutput(multiWriter)
	warningLog.SetOutput(multiWriter)
	infoLog.SetOutput(multiWriter)
	if debugLog != nil {
		debugLog.SetOutput(multiWriter)
	}

	return nil
}

// cleanOldBackups حذف النسخ الاحتياطية القديمة
func cleanOldBackups(config *LogConfig) error {
	pattern := config.LogPath + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}

	if len(matches) <= config.MaxBackups {
		return nil
	}

	// ترتيب الملفات حسب التاريخ
	type backup struct {
		path string
		time time.Time
	}
	var backups []backup

	for _, match := range matches {
		t, err := time.Parse("20060102150405", filepath.Ext(match)[1:])
		if err != nil {
			continue
		}
		backups = append(backups, backup{match, t})
	}

	// ترتيب النسخ الاحتياطية حسب التاريخ
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].time.Before(backups[j].time)
	})

	// حذف أقدم الملفات
	for i := 0; i < len(backups)-config.MaxBackups; i++ {
		if err := os.Remove(backups[i].path); err != nil {
			LogWarning(fmt.Sprintf("فشل في حذف النسخة الاحتياطية: %s", backups[i].path))
		}
	}

	return nil
}

// Close إغلاق ملف السجلات
func Close() {
	mu.Lock()
	defer mu.Unlock()

	if logFile != nil {
		logFile.Close()
	}
}

// GetLogFile يعيد مسار ملف السجلات الحالي
func GetLogFile() string {
	mu.Lock()
	defer mu.Unlock()

	if logFile == nil {
		return ""
	}

	return logFile.Name()
}
