package utils

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// CheckSystemRequirements يتحقق من توفر المتطلبات الأساسية للنظام
func CheckSystemRequirements() error {
	// التحقق من إصدار Go
	if err := checkGoVersion(); err != nil {
		return err
	}

	// التحقق من الصلاحيات
	if err := checkPermissions(); err != nil {
		return err
	}

	// التحقق من توفر الأدوات المطلوبة
	if err := checkRequiredTools(); err != nil {
		return err
	}

	return nil
}

// checkGoVersion يتحقق من إصدار Go
func checkGoVersion() error {
	requiredVersion := "1.19"
	currentVersion := runtime.Version()
	if currentVersion < "go"+requiredVersion {
		return fmt.Errorf("إصدار Go المطلوب هو %s أو أحدث، الإصدار الحالي: %s", requiredVersion, currentVersion)
	}
	return nil
}

// checkPermissions يتحقق من صلاحيات المستخدم
func checkPermissions() error {
	// التحقق من صلاحية الكتابة في المجلد الحالي
	testFile := ".permission_test"
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("لا توجد صلاحيات كافية للكتابة في المجلد الحالي: %v", err)
	}
	os.Remove(testFile)

	// التحقق من صلاحية إنشاء المجلدات
	testDir := ".dir_test"
	if err := os.Mkdir(testDir, 0755); err != nil {
		return fmt.Errorf("لا توجد صلاحيات كافية لإنشاء المجلدات: %v", err)
	}
	os.Remove(testDir)

	return nil
}

// checkRequiredTools يتحقق من توفر الأدوات المطلوبة
func checkRequiredTools() error {
	requiredTools := []string{
		"git",    // للتحكم في الإصدارات
		"curl",   // للطلبات HTTP
		"nmap",   // لفحص المنافذ (اختياري)
	}

	for _, tool := range requiredTools {
		if err := checkTool(tool); err != nil {
			if tool == "nmap" {
				// nmap اختياري، نكتفي بالتحذير
				fmt.Printf("تحذير: أداة %s غير متوفرة. بعض الوظائف قد لا تعمل.\n", tool)
				continue
			}
			return fmt.Errorf("الأداة المطلوبة %s غير متوفرة: %v", tool, err)
		}
	}

	return nil
}

// checkTool يتحقق من توفر أداة معينة
func checkTool(tool string) error {
	_, err := exec.LookPath(tool)
	return err
}

// ReadTargetsFile يقرأ ملف الأهداف ويعيد قائمة بالأهداف
func ReadTargetsFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// تنظيف وتصفية الأهداف
	targets := []string{}
	for _, line := range strings.Split(string(content), "\n") {
		target := strings.TrimSpace(line)
		if target != "" && !strings.HasPrefix(target, "#") {
			targets = append(targets, target)
		}
	}

	return targets, nil
} 