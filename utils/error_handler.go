package utils

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"vulne_scanner/logs"
)

// ErrorType نوع الخطأ
type ErrorType int

const (
	NetworkError ErrorType = iota
	FileError
	ConfigError
	ScanError
	ValidationError
)

// CustomError خطأ مخصص
type CustomError struct {
	Type    ErrorType
	Message string
	Time    time.Time
	Stack   string
}

// Error يطبق واجهة error
func (e *CustomError) Error() string {
	return fmt.Sprintf("[%s] %s: %s\n%s", e.Time.Format(time.RFC3339), e.getErrorTypeName(), e.Message, e.Stack)
}

// getErrorTypeName يعيد اسم نوع الخطأ
func (e *CustomError) getErrorTypeName() string {
	switch e.Type {
	case NetworkError:
		return "خطأ في الشبكة"
	case FileError:
		return "خطأ في الملف"
	case ConfigError:
		return "خطأ في الإعدادات"
	case ScanError:
		return "خطأ في الفحص"
	case ValidationError:
		return "خطأ في التحقق"
	default:
		return "خطأ غير معروف"
	}
}

// NewError ينشئ خطأ جديد
func NewError(errType ErrorType, message string) *CustomError {
	// جمع معلومات Stack Trace
	var stack strings.Builder
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	stack.Write(buf[:n])

	err := &CustomError{
		Type:    errType,
		Message: message,
		Time:    time.Now(),
		Stack:   stack.String(),
	}

	// تسجيل الخطأ
	logs.LogError(err, err.Message)

	return err
}

// HandleError يعالج الخطأ ويتخذ الإجراء المناسب
func HandleError(err error) error {
	if err == nil {
		return nil
	}

	// تصنيف الأخطاء
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return NewError(TimeoutError, "انتهت مهلة العملية")
	case errors.Is(err, context.Canceled):
		return NewError(CanceledError, "تم إلغاء العملية")
	case errors.Is(err, os.ErrPermission):
		return NewError(PermissionError, "خطأ في الصلاحيات")
	}

	// معالجة الأخطاء المخصصة
	var customErr *CustomError
	if errors.As(err, &customErr) {
		logs.LogError(customErr, customErr.Message)
		return customErr
	}

	// تغليف الأخطاء غير المعروفة
	return NewError(UnknownError, err.Error())
}

// دوال معالجة الأخطاء المختلفة
func handleNetworkError(err *CustomError) {
	logs.LogError(err, "فشل في الاتصال بالشبكة")
	// يمكن إضافة محاولات إعادة الاتصال هنا
}

func handleFileError(err *CustomError) {
	logs.LogError(err, "فشل في العمليات على الملفات")
	// يمكن إنشاء نسخة احتياطية أو محاولة الإصلاح
}

func handleConfigError(err *CustomError) {
	logs.LogError(err, "خطأ في الإعدادات")
	// يمكن محاولة تحميل إعدادات افتراضية
}

func handleScanError(err *CustomError) {
	logs.LogError(err, "فشل في عملية الفحص")
	// يمكن محاولة إعادة تشغيل الفحص
}

func handleValidationError(err *CustomError) {
	logs.LogError(err, "فشل في التحقق من الصحة")
	// يمكن طلب مدخلات صحيحة
}

// IsNetworkError يتحقق مما إذا كان الخطأ متعلق بالشبكة
func IsNetworkError(err error) bool {
	if customErr, ok := err.(*CustomError); ok {
		return customErr.Type == NetworkError
	}
	return false
}

// IsFileError يتحقق مما إذا كان الخطأ متعلق بالملفات
func IsFileError(err error) bool {
	if customErr, ok := err.(*CustomError); ok {
		return customErr.Type == FileError
	}
	return false
}
