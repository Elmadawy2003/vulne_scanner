package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"vulne_scanner/config"
	"vulne_scanner/logs"
	"vulne_scanner/reports"
	"vulne_scanner/scanning"
	"vulne_scanner/types"
	"vulne_scanner/utils"
)

var (
	target      string
	targetsFile string
	outputPath  string
	format      string
	configFile  string
)

func init() {
	// تهيئة الإعدادات الافتراضية
	target = os.Getenv("VULNE_TARGET")
	targetsFile = os.Getenv("VULNE_TARGETS_FILE")
	outputPath = os.Getenv("VULNE_OUTPUT_PATH")
	format = os.Getenv("VULNE_OUTPUT_FORMAT")
	configFile = os.Getenv("VULNE_CONFIG_FILE")

	// تحميل الإعدادات من سطر الأوامر
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-target":
			if i+1 < len(os.Args) {
				target = os.Args[i+1]
				i++
			}
		case "-targets":
			if i+1 < len(os.Args) {
				targetsFile = os.Args[i+1]
				i++
			}
		case "-output":
			if i+1 < len(os.Args) {
				outputPath = os.Args[i+1]
				i++
			}
		case "-format":
			if i+1 < len(os.Args) {
				format = os.Args[i+1]
				i++
			}
		case "-config":
			if i+1 < len(os.Args) {
				configFile = os.Args[i+1]
				i++
			}
		}
	}

	// تعيين القيم الافتراضية
	if outputPath == "" {
		outputPath = "reports/scan_report"
	}
	if format == "" {
		format = "html"
	}
	if configFile == "" {
		configFile = "config/config.yaml"
	}
}

func main() {
	// تهيئة السياق مع إمكانية الإلغاء
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// معالجة إشارات النظام
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go handleSignals(sigChan, cancel)

	// تهيئة السجلات
	if err := logs.Initialize(true); err != nil {
		fmt.Printf("فشل في تهيئة السجلات: %v\n", err)
		os.Exit(1)
	}

	// تحميل الإعدادات
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		logs.LogError(err, "فشل في تحميل ملف الإعدادات")
		os.Exit(1)
	}

	// التحقق من المتطلبات الأساسية
	if err := utils.CheckSystemRequirements(); err != nil {
		logs.LogError(err, "فشل في التحقق من المتطلبات الأساسية")
		os.Exit(1)
	}

	// تحضير قائمة الأهداف
	targets, err := prepareTargets()
	if err != nil {
		logs.LogError(err, "فشل في تحضير قائمة الأهداف")
		os.Exit(1)
	}

	// إنشاء مجلدات التقارير والسجلات
	if err := createRequiredDirectories(); err != nil {
		logs.LogError(err, "فشل في إنشاء المجلدات المطلوبة")
		os.Exit(1)
	}

	// إنشاء الماسح
	scanner := scanning.NewScanner(cfg)

	// تشغيل الفحص
	results, err := scanner.ScanTargets(ctx, targets)
	if err != nil {
		logs.LogError(err, "فشل في عملية الفحص")
		os.Exit(1)
	}

	// إنشاء التقرير
	reporter := reports.NewReporter(cfg)
	for i, result := range results {
		outputFile := fmt.Sprintf("%s_%d.%s", outputPath, i+1, format)
		if err := reporter.GenerateReport(result.Vulnerabilities, result.Target, format, outputFile); err != nil {
			logs.LogError(err, "فشل في إنشاء التقرير")
			os.Exit(1)
		}
	}

	logs.LogInfo("تم إكمال عملية الفحص بنجاح")
}

func handleSignals(sigChan chan os.Signal, cancel context.CancelFunc) {
	<-sigChan
	logs.LogWarning("تم استلام إشارة إيقاف، جاري الإنهاء بأمان...")
	cancel()
}

func prepareTargets() ([]string, error) {
	var targets []string

	if target != "" {
		targets = append(targets, target)
	}

	if targetsFile != "" {
		fileTargets, err := utils.ReadTargetsFile(targetsFile)
		if err != nil {
			return nil, fmt.Errorf("فشل في قراءة ملف الأهداف: %v", err)
		}
		targets = append(targets, fileTargets...)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("يجب تحديد هدف واحد على الأقل باستخدام -target أو -targets")
	}

	return targets, nil
}

func createRequiredDirectories() error {
	dirs := []string{
		"logs",
		"reports",
		filepath.Dir(outputPath),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("فشل في إنشاء المجلد %s: %v", dir, err)
		}
	}

	return nil
}
