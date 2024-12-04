package reports

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"vulne_scanner/scanning"
)

// Reporter واجهة لإنشاء التقارير
type Reporter interface {
	GenerateReport(results *scanning.ScanResults, outputPath string) error
}

// NewReporter ينشئ مولد تقارير جديد حسب النوع المطلوب
func NewReporter(format string) (Reporter, error) {
	switch format {
	case "json":
		return &JSONReporter{}, nil
	case "csv":
		return &CSVReporter{}, nil
	case "html":
		return &HTMLReporter{}, nil
	default:
		return nil, fmt.Errorf("نوع التقرير غير مدعوم: %s", format)
	}
}

// JSONReporter مولد تقارير JSON
type JSONReporter struct{}

// GenerateReport ينشئ تقرير بصيغة JSON
func (r *JSONReporter) GenerateReport(results *scanning.ScanResults, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("فشل في إنشاء ملف التقرير: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// CSVReporter مولد تقارير CSV
type CSVReporter struct{}

// GenerateReport ينشئ تقرير بصيغة CSV
func (r *CSVReporter) GenerateReport(results *scanning.ScanResults, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("فشل في إنشاء ملف التقرير: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// كتابة رأس الجدول
	headers := []string{"الهدف", "نوع الثغرة", "الخطورة", "الوصف", "الحل"}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("فشل في كتابة رأس التقرير: %v", err)
	}

	// كتابة البيانات
	for _, result := range results.Results {
		for _, vuln := range result.Vulnerabilities {
			record := []string{
				result.Target,
				vuln.Type,
				vuln.Severity,
				vuln.Description,
				vuln.Solution,
			}
			if err := writer.Write(record); err != nil {
				return fmt.Errorf("فشل في كتابة سجل: %v", err)
			}
		}
	}

	return nil
}

// HTMLReporter مولد تقارير HTML
type HTMLReporter struct{}

// GenerateReport ينشئ تقرير بصيغة HTML
func (r *HTMLReporter) GenerateReport(results *scanning.ScanResults, outputPath string) error {
	// قراءة قالب HTML
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("فشل في تحليل قالب HTML: %v", err)
	}

	// إنشاء ملف التقرير
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("فشل في إنشاء ملف التقرير: %v", err)
	}
	defer file.Close()

	// إعداد بيانات التقرير
	data := struct {
		Results   *scanning.ScanResults
		Generated time.Time
	}{
		Results:   results,
		Generated: time.Now(),
	}

	// توليد التقرير
	return tmpl.Execute(file, data)
}

// قالب HTML للتقرير
const htmlTemplate = `
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير فحص الثغرات الأمنية</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .vulnerability {
            border: 1px solid #ddd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .critical { border-right: 5px solid #dc3545; }
        .high { border-right: 5px solid #fd7e14; }
        .medium { border-right: 5px solid #ffc107; }
        .low { border-right: 5px solid #28a745; }
        .info { border-right: 5px solid #17a2b8; }
        .meta {
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>تقرير فحص الثغرات الأمنية</h1>
        
        <div class="meta">
            <p>تاريخ التقرير: {{.Generated.Format "2006-01-02 15:04:05"}}</p>
            <p>وقت البدء: {{.Results.StartTime.Format "2006-01-02 15:04:05"}}</p>
            <p>وقت الانتهاء: {{.Results.EndTime.Format "2006-01-02 15:04:05"}}</p>
            <p>عدد الأهداف: {{.Results.TotalTargets}}</p>
        </div>

        <div class="summary">
            <h2>ملخص النتائج</h2>
            {{range .Results.Results}}
            <h3>الهدف: {{.Target}}</h3>
            <p>عدد الثغرات: {{len .Vulnerabilities}}</p>
            {{end}}
        </div>

        {{range .Results.Results}}
        <div class="target-results">
            <h2>نتائج فحص {{.Target}}</h2>
            {{range .Vulnerabilities}}
            <div class="vulnerability {{.Severity}}">
                <h3>{{.Type}}</h3>
                <p><strong>مستوى الخطورة:</strong> {{.Severity}}</p>
                <p><strong>الوصف:</strong> {{.Description}}</p>
                {{if .Evidence}}
                <p><strong>الدليل:</strong> {{.Evidence}}</p>
                {{end}}
                {{if .Solution}}
                <p><strong>الحل:</strong> {{.Solution}}</p>
                {{end}}
            </div>
            {{end}}
        </div>
        {{end}}
    </div>
</body>
</html>
` 