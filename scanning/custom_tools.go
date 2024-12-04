package scanning

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"vulne_scanner/logs"
)

// تحديث قائمة الأدوات المدعومة
type Tool struct {
	name        string
	command     string
	args        []string
	parseOutput func(string) ([]Vulnerability, error)
}

// توسيع CustomTools
type CustomTools struct {
	stop        chan struct{}
	mu          sync.Mutex
	tools       []Tool
	concurrency int
	timeout     time.Duration
}

func NewCustomTools() *CustomTools {
	ct := &CustomTools{
		stop:        make(chan struct{}),
		concurrency: 5,
		timeout:     10 * time.Minute,
	}
	
	// تكوين قائمة الأدوات المدعومة
	ct.tools = []Tool{
		// أدوات فحص الويب
		{
			name:    "SQLMap",
			command: "sqlmap",
			args:    []string{"--batch", "--random-agent", "--level", "5", "--risk", "3", "--threads", "10"},
			parseOutput: parseSQLMapOutput,
		},
		{
			name:    "Nikto",
			command: "nikto",
			args:    []string{"-Format", "json", "-Tuning", "x 6"},
			parseOutput: parseNiktoOutput,
		},
		{
			name:    "WPScan",
			command: "wpscan",
			args:    []string{"--format", "json", "--enumerate", "vp,vt,tt,cb,dbe,u,m"},
			parseOutput: parseWPScanOutput,
		},
		// أدوات فحص SSL/TLS
		{
			name:    "SSLScan",
			command: "sslscan",
			args:    []string{"--no-colour", "--show-certificate"},
			parseOutput: parseSSLScanOutput,
		},
		{
			name:    "Testssl",
			command: "testssl.sh",
			args:    []string{"--severity", "HIGH", "--quiet", "--json"},
			parseOutput: parseTestSSLOutput,
		},
		// أدوات فحص الخدمات
		{
			name:    "Nmap",
			command: "nmap",
			args:    []string{"-sV", "-sC", "--script", "vuln", "-oX", "-"},
			parseOutput: parseNmapOutput,
		},
		{
			name:    "Masscan",
			command: "masscan",
			args:    []string{"-p1-65535", "--rate", "1000"},
			parseOutput: parseMasscanOutput,
		},
		// أدوات فحص التطبيقات
		{
			name:    "XSStrike",
			command: "xsstrike",
			args:    []string{"--crawl", "--blind", "--params"},
			parseOutput: parseXSStrikeOutput,
		},
		{
			name:    "Commix",
			command: "commix",
			args:    []string{"--batch", "--output-dir", "results"},
			parseOutput: parseCommixOutput,
		},
		// أدوات فحص API
		{
			name:    "Arjun",
			command: "arjun",
			args:    []string{"-t", "10", "--json"},
			parseOutput: parseArjunOutput,
		},
		{
			name:    "JWT_Tool",
			command: "jwt_tool",
			args:    []string{"-M", "pb"},
			parseOutput: parseJWTToolOutput,
		},
		// إضافة أدوات جديدة في NewCustomTools
		{
			name:    "Dirb",
			command: "dirb",
			args:    []string{"-r", "-o", "dirb_output.txt"},
			parseOutput: parseDirbOutput,
		},
		{
			name:    "Subfinder",
			command: "subfinder",
			args:    []string{"-silent", "-all"},
			parseOutput: parseSubfinderOutput,
		},
		{
			name:    "Gobuster",
			command: "gobuster",
			args:    []string{"dir", "-q", "-n", "-e"},
			parseOutput: parseGobusterOutput,
		},
		{
			name:    "Dalfox",
			command: "dalfox",
			args:    []string{"url", "--silence", "--no-color"},
			parseOutput: parseDalfoxOutput,
		},
		{
			name:    "Nuclei",
			command: "nuclei",
			args:    []string{"-silent", "-severity", "critical,high"},
			parseOutput: parseNucleiOutput,
		},
		{
			name:    "Gitleaks",
			command: "gitleaks",
			args:    []string{"detect", "--no-git", "-v"},
			parseOutput: parseGitleaksOutput,
		},
		{
			name:    "Trufflehog",
			command: "trufflehog",
			args:    []string{"--json", "--entropy=true"},
			parseOutput: parseTrufflehogOutput,
		},
		{
			name:    "Semgrep",
			command: "semgrep",
			args:    []string{"--config", "auto", "--json"},
			parseOutput: parseSemgrepOutput,
		},
		// إضافة أدوات متقدمة جديدة
		{
			name:    "Jaeles",
			command: "jaeles",
			args:    []string{"scan", "-c", "50", "-s", "/signatures/", "-L", "info"},
			parseOutput: parseJaelesOutput,
		},
		{
			name:    "Katana",
			command: "katana",
			args:    []string{"-js-crawl", "-headless", "-automatic-form-fill"},
			parseOutput: parseKatanaOutput,
		},
		{
			name:    "Hakrawler",
			command: "hakrawler",
			args:    []string{"-d", "3", "-h", "true", "-s", "true"},
			parseOutput: parseHakrawlerOutput,
		},
		
		// أدوات فحص الأمان المتقدمة
		{
			name:    "Nuclei-Advanced",
			command: "nuclei",
			args:    []string{
				"-severity", "critical,high,medium",
				"-templates", "cves,vulnerabilities,exposures",
				"-headless",
				"-follow-redirects",
				"-attack-type", "all",
			},
			parseOutput: parseNucleiAdvancedOutput,
		},
		
		// أدوات فحص التكوين
		{
			name:    "CloudSploit",
			command: "cloudsploit",
			args:    []string{"scan", "--json"},
			parseOutput: parseCloudSploitOutput,
		},
		{
			name:    "Prowler",
			command: "prowler",
			args:    []string{"-M", "json", "-S"},
			parseOutput: parseProwlerOutput,
		},
		
		// أدوات فحص الشبكات المتقدمة
		{
			name:    "Naabu",
			command: "naabu",
			args:    []string{"-rate", "1000", "-verify", "-stats"},
			parseOutput: parseNaabuOutput,
		},
		{
			name:    "DNSx",
			command: "dnsx",
			args:    []string{"-wd", "-resp", "-retry", "3"},
			parseOutput: parseDNSxOutput,
		},
		
		// أدوات فحص الثغرات المتقدمة
		{
			name:    "CRLFuzz",
			command: "crlfuzz",
			args:    []string{"-s", "high", "-o", "json"},
			parseOutput: parseCRLFuzzOutput,
		},
		{
			name:    "Paramspider",
			command: "paramspider",
			args:    []string{"--level", "3", "--exclude", "jpg,jpeg,gif,css,js"},
			parseOutput: parseParamspiderOutput,
		},
		
		// أدوات فحص الكود
		{
			name:    "GoSec",
			command: "gosec",
			args:    []string{"-fmt=json", "-confidence=high", "./..."},
			parseOutput: parseGoSecOutput,
		},
		{
			name:    "Safety",
			command: "safety",
			args:    []string{"check", "--json", "--full-report"},
			parseOutput: parseSafetyOutput,
		},
		// إضافة أدوات متخصصة جديدة
		{
			name:    "InQL",
			command: "inql",
			args:    []string{"--introspection", "--generate-report"},
			parseOutput: parseInQLOutput,
		},
		{
			name:    "GraphQLmap",
			command: "graphqlmap",
			args:    []string{"--detect-introspection", "--detect-mutations"},
			parseOutput: parseGraphQLmapOutput,
		},
		{
			name:    "Trivy",
			command: "trivy",
			args:    []string{"fs", "--security-checks", "vuln,config,secret", "--format", "json"},
			parseOutput: parseTrivyOutput,
		},
		{
			name:    "Grype",
			command: "grype",
			args:    []string{"--scope", "all-layers", "--output", "json"},
			parseOutput: parseGrypeOutput,
		},
		{
			name:    "TFSec",
			command: "tfsec",
			args:    []string{"--format", "json", "--minimum-severity", "HIGH"},
			parseOutput: parseTFSecOutput,
		},
		{
			name:    "Checkov",
			command: "checkov",
			args:    []string{"-o", "json", "--quiet", "--compact"},
			parseOutput: parseCheckovOutput,
		},
		{
			name:    "Ghauri",
			command: "ghauri",
			args:    []string{"-l", "5", "--batch", "--tamper=base64encode"},
			parseOutput: parseGhauriOutput,
		},
		{
			name:    "Corsy",
			command: "corsy",
			args:    []string{"--quiet", "--headers", "--methods"},
			parseOutput: parseCorsyOutput,
		},
		// إضافة أدوات متخصصة جديدة
		{
			name:    "CloudMapper",
			command: "cloudmapper",
			args:    []string{"--scan", "--report", "--format=json"},
			parseOutput: parseCloudMapperOutput,
		},
		{
			name:    "ScoutSuite",
			command: "scout",
			args:    []string{"--format", "json", "--report-dir", "./reports"},
			parseOutput: parseScoutSuiteOutput,
		},

		// أدوات فحص الحاويات والـ Kubernetes
		{
			name:    "Kubescape",
			command: "kubescape",
			args:    []string{"scan", "--format", "json", "--severity", "high,critical"},
			parseOutput: parseKubescapeOutput,
		},
		{
			name:    "KubeSec",
			command: "kubesec",
			args:    []string{"scan", "--format", "json", "--threshold", "high"},
			parseOutput: parseKubeSecOutput,
		},

		// أدوات فحص التطبيقات المتقدمة
		{
			name:    "Caido",
			command: "caido",
			args:    []string{"--headless", "--deep-scan", "--output-json"},
			parseOutput: parseCaidoOutput,
		},
		{
			name:    "Jaeles-Custom",
			command: "jaeles",
			args: []string{
				"scan",
				"-s", "/signatures/cves/",
				"-s", "/signatures/common/",
				"-L", "info",
				"-v",
			},
			parseOutput: parseJaelesCustomOutput,
		},

		// أدوات فحص الذكاء الاصطناعي والتعلم الآلي
		{
			name:    "MLScan",
			command: "mlscan",
			args:    []string{"--model-analysis", "--data-leakage-check"},
			parseOutput: parseMLScanOutput,
		},
		{
			name:    "AISecurityAnalyzer",
			command: "aisec",
			args:    []string{"--comprehensive", "--model-security"},
			parseOutput: parseAISecOutput,
		},

		// أدوات فحص البلوكتشين
		{
			name:    "Mythril",
			command: "myth",
			args:    []string{"analyze", "--execution-timeout", "90", "-o", "json"},
			parseOutput: parseMythrilOutput,
		},
		{
			name:    "Slither",
			command: "slither",
			args:    []string{"--json", "-"},
			parseOutput: parseSlitherOutput,
		},
	}
	
	return ct
}

// تحسين دالة Scan
func (ct *CustomTools) Scan(ctx context.Context, target string) ([]Vulnerability, error) {
	var allResults []Vulnerability
	var wg sync.WaitGroup
	resultsChan := make(chan []Vulnerability, len(ct.tools))
	errorsChan := make(chan error, len(ct.tools))
	
	// إنشاء مجمع للعمليات المتزامنة
	semaphore := make(chan struct{}, ct.concurrency)
	
	for _, tool := range ct.tools {
		wg.Add(1)
		go func(t Tool) {
			defer wg.Done()
			
			// استخدام السيمافور للتحكم في التزامن
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// تحضير الأمر مع إضافة الهدف
			args := append(t.args, target)
			results, err := ct.runToolWithTimeout(ctx, t, args)
			if err != nil {
				errorsChan <- fmt.Errorf("خطأ في تنفيذ %s: %v", t.name, err)
				return
			}
			
			resultsChan <- results
		}(tool)
	}
	
	// جمع النتائج
	go func() {
		wg.Wait()
		close(resultsChan)
		close(errorsChan)
	}()
	
	// معالجة النتائج والأخطاء
	for {
		select {
		case results, ok := <-resultsChan:
			if !ok {
				return allResults, nil
			}
			allResults = append(allResults, results...)
			
		case err := <-errorsChan:
			logs.LogError(err, "خطأ في تنفيذ أداة")
			
		case <-ctx.Done():
			return allResults, ctx.Err()
		}
	}
}

// تشغيل الأداة مع مهلة زمنية
func (ct *CustomTools) runToolWithTimeout(ctx context.Context, tool Tool, args []string) ([]Vulnerability, error) {
	ctx, cancel := context.WithTimeout(ctx, ct.timeout)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, tool.command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("انتهت مهلة تنفيذ %s", tool.name)
		}
		return nil, err
	}
	
	return tool.parseOutput(string(output))
}

// دوال تحليل مخرجات الأدوات
func parseSQLMapOutput(output string) ([]Vulnerability, error) {
	var vulns []Vulnerability
	
	if strings.Contains(output, "sqlmap identified") {
		vuln := Vulnerability{
			Name:        "SQL Injection",
			Description: "تم اكتشاف نقطة ضعف حقن SQL",
			Severity:    "high",
			Details:     output,
		}
		vulns = append(vulns, vuln)
	}
	
	return vulns, nil
}

func parseNmapOutput(output string) ([]Vulnerability, error) {
	var vulns []Vulnerability
	
	// تحليل مخرجات XML من Nmap
	doc, err := xmlquery.Parse(strings.NewReader(output))
	if err != nil {
		return nil, err
	}

	// البحث عن الثغرات في نتائج المسح
	for _, host := range xmlquery.Find(doc, "//host") {
		// فحص الخدمات المفتوحة
		for _, port := range xmlquery.Find(host, "//port[@state='open']") {
			service := port.SelectAttr("service")
			if service != "" {
				// فحص إصدارات الخدمات القديمة
				if version := port.SelectAttr("version"); version != "" {
					vulns = append(vulns, Vulnerability{
						Name:        fmt.Sprintf("Outdated Service: %s %s", service, version),
						Description: "تم اكتشاف خدمة بإصدار قديم قد يحتوي على ثغرات",
						Severity:    "medium",
					})
				}
			}
		}

		// فحص نتائج النصوص البرمجية
		for _, script := range xmlquery.Find(host, "//script") {
			if script.SelectAttr("id") == "vuln" {
				vulns = append(vulns, Vulnerability{
					Name:        script.SelectAttr("output"),
					Description: "تم اكتشاف ثغرة بواسطة نصوص Nmap",
					Severity:    "high",
				})
			}
		}
	}
	
	return vulns, nil
}

func parseWPScanOutput(output string) ([]Vulnerability, error) {
	var vulns []Vulnerability
	var result struct {
		Vulnerabilities struct {
			Plugins     []WPVulnerability `json:"plugins"`
			Themes     []WPVulnerability `json:"themes"`
			WordPress []WPVulnerability `json:"wordpress"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, err
	}

	// تحليل ثغرات الإضافات
	for _, plugin := range result.Vulnerabilities.Plugins {
		vulns = append(vulns, Vulnerability{
			Name:        fmt.Sprintf("WordPress Plugin Vulnerability: %s", plugin.Name),
			Description: plugin.Description,
			Severity:    plugin.Severity,
			CVE:        plugin.References.CVE,
		})
	}

	// تحليل ثغرات القوالب
	for _, theme := range result.Vulnerabilities.Themes {
		vulns = append(vulns, Vulnerability{
			Name:        fmt.Sprintf("WordPress Theme Vulnerability: %s", theme.Name),
			Description: theme.Description,
			Severity:    theme.Severity,
			CVE:        theme.References.CVE,
		})
	}

	return vulns, nil
}

func parseSSLScanOutput(output string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// فحص البروتوكولات الضعيفة
	if strings.Contains(output, "SSLv2") || strings.Contains(output, "SSLv3") {
		vulns = append(vulns, Vulnerability{
			Name:        "Weak SSL/TLS Protocol",
			Description: "تم اكتشاف دعم لبروتوكولات SSL/TLS ضعيفة",
			Severity:    "high",
		})
	}

	// فحص الشهادات منتهية الصلاحية
	if strings.Contains(output, "Certificate Expired") {
		vulns = append(vulns, Vulnerability{
			Name:        "Expired SSL Certificate",
			Description: "الشهادة الرقمية منتهية الصلاحية",
			Severity:    "medium",
		})
	}

	// فحص خوارزميات التشفير الضعيفة
	weakCiphers := []string{"RC4", "DES", "MD5"}
	for _, cipher := range weakCiphers {
		if strings.Contains(output, cipher) {
			vulns = append(vulns, Vulnerability{
				Name:        fmt.Sprintf("Weak Cipher: %s", cipher),
				Description: "تم اكتشاف استخدام خوارزمية تشفير ضعيفة",
				Severity:    "high",
			})
		}
	}

	return vulns, nil
}

func parseXSStrikeOutput(output string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// تحليل نتائج XSStrike
	if strings.Contains(output, "Vulnerable") {
		// استخراج التفاصيل باستخدام التعبيرات المنتظمة
		re := regexp.MustCompile(`URL: (.*?)\nVector: (.*?)\nContext: (.*?)\n`)
		matches := re.FindAllStringSubmatch(output, -1)

		for _, match := range matches {
			if len(match) >= 4 {
				vulns = append(vulns, Vulnerability{
					Name:        "Cross-Site Scripting (XSS)",
					Description: fmt.Sprintf("تم اكتشاف ثغرة XSS في: %s\nVector: %s\nContext: %s", 
						match[1], match[2], match[3]),
					Severity:    "high",
					URL:         match[1],
				})
			}
		}
	}

	return vulns, nil
}

// إضافة دوال تحليل جديدة للثغرات المتقدمة

// تحليل نتائج فحص API
func parseAPISecurityOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    
    // فحص مشاكل المصادقة في API
    if strings.Contains(output, "Authentication Bypass") {
        vulns = append(vulns, Vulnerability{
            Type:        APIVulnerabilities,
            Name:        "API Authentication Bypass",
            Description: "تم اكتشاف إمكانية تجاوز المصادقة في API",
            Severity:    "critical",
            CVSS:        9.0,
        })
    }

    // فحص Rate Limiting
    if strings.Contains(output, "Rate Limit Bypass") {
        vulns = append(vulns, Vulnerability{
            Type:        APIVulnerabilities,
            Name:        "API Rate Limit Bypass",
            Description: "تم اكتشاف إمكانية تجاوز حد معدل الطلبات",
            Severity:    "high",
            CVSS:        7.5,
        })
    }

    return vulns, nil
}

// تحليل نتائج فحص WebSocket
func parseWebSocketOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    // فحص مشاكل المصادقة في WebSocket
    if strings.Contains(output, "WebSocket Authentication") {
        vulns = append(vulns, Vulnerability{
            Type:        WebSocketVulnerabilities,
            Name:        "WebSocket Authentication Weakness",
            Description: "ضعف في آلية مصادقة اتصالات WebSocket",
            Severity:    "high",
            CVSS:        8.0,
        })
    }

    // فحص تشفير الاتصالات
    if strings.Contains(output, "Unencrypted WebSocket") {
        vulns = append(vulns, Vulnerability{
            Type:        WebSocketVulnerabilities,
            Name:        "Unencrypted WebSocket Communication",
            Description: "اتصالات WebSocket غير مشفرة",
            Severity:    "medium",
            CVSS:        6.5,
        })
    }

    return vulns, nil
}

// تحليل نتائج فحص منطق العمل
func parseBusinessLogicOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    patterns := map[string]Vulnerability{
        "Price Manipulation": {
            Type:        BusinessLogicVulnerabilities,
            Name:        "Price Manipulation",
            Description: "إمكانية التلاعب بالأسعار",
            Severity:    "critical",
            CVSS:        9.0,
        },
        "Order Flow Bypass": {
            Type:        BusinessLogicVulnerabilities,
            Name:        "Order Flow Bypass",
            Description: "إمكانية تجاوز تسلسل عملية الطلب",
            Severity:    "high",
            CVSS:        8.0,
        },
        "Access Control": {
            Type:        BusinessLogicVulnerabilities,
            Name:        "Business Logic Access Control",
            Description: "ثغرات في التحكم بالوصول لمنطق العمل",
            Severity:    "high",
            CVSS:        8.0,
        },
    }

    for pattern, vuln := range patterns {
        if strings.Contains(output, pattern) {
            vulns = append(vulns, vuln)
        }
    }

    return vulns, nil
}

// تحليل نتائج فحص NoSQL
func parseNoSQLOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    // فحص حقن NoSQL
    if strings.Contains(output, "$where") || strings.Contains(output, "$ne") {
        vulns = append(vulns, Vulnerability{
            Type:        NoSQLInjection,
            Name:        "NoSQL Injection",
            Description: "تم اكتشاف إمكانية حقن استعلامات NoSQL",
            Severity:    "high",
            CVSS:        8.0,
        })
    }

    // فحص تجاوز المصادقة
    if strings.Contains(output, "Authentication Bypass") {
        vulns = append(vulns, Vulnerability{
            Type:        NoSQLInjection,
            Name:        "NoSQL Authentication Bypass",
            Description: "إمكانية تجاوز المصادقة باستخدام حقن NoSQL",
            Severity:    "critical",
            CVSS:        9.0,
        })
    }

    return vulns, nil
}

// تحليل نتائج فحص SSTI
func parseTemplateInjectionOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    templates := map[string]struct {
        engine string
        severity string
    }{
        "{{7*7}}": {"Twig/Jinja2", "high"},
        "${7*7}":  {"JSP/Spring", "high"},
        "<%= 7*7 %>": {"ERB", "high"},
        "#{7*7}":  {"Ruby", "high"},
    }

    for payload, info := range templates {
        if strings.Contains(output, "49") && strings.Contains(output, payload) {
            vulns = append(vulns, Vulnerability{
                Type:        ServerSideTemplateInjection,
                Name:        fmt.Sprintf("SSTI in %s", info.engine),
                Description: fmt.Sprintf("تم اكتشاف إمكانية حقن قوالب في محرك %s", info.engine),
                Severity:    info.severity,
                CVSS:        8.5,
                Proof:       fmt.Sprintf("Payload: %s, Result: 49", payload),
            })
        }
    }

    return vulns, nil
}

// تحليل نتائج فحص المكونات الضعيفة
func parseVulnerableComponentsOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    // تحليل نتائج npm audit/yarn audit
    if strings.Contains(output, "High") || strings.Contains(output, "Critical") {
        re := regexp.MustCompile(`(High|Critical).*?([a-zA-Z-]+)@(\d+\.\d+\.\d+)`)
        matches := re.FindAllStringSubmatch(output, -1)
        
        for _, match := range matches {
            vulns = append(vulns, Vulnerability{
                Type:        UsingVulnerableComponents,
                Name:        fmt.Sprintf("Vulnerable %s Package", match[2]),
                Description: fmt.Sprintf("إصدار ضعيف من حزمة %s: %s", match[2], match[3]),
                Severity:    strings.ToLower(match[1]),
                CVSS:        7.5,
            })
        }
    }

    return vulns, nil
}

// تحليل نتائج فحص LDAP
func parseLDAPInjectionOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    patterns := []struct {
        pattern string
        name    string
        desc    string
    }{
        {
            pattern: "*)(uid=*",
            name:    "LDAP Injection - Wildcard",
            desc:    "إمكانية استخدام العلامة النجمية في استعلامات LDAP",
        },
        {
            pattern: ")(|(uid=*",
            name:    "LDAP Injection - OR Condition",
            desc:    "إمكانية إضافة شروط OR في استعلامات LDAP",
        },
    }

    for _, p := range patterns {
        if strings.Contains(output, p.pattern) {
            vulns = append(vulns, Vulnerability{
                Type:        LDAPInjection,
                Name:        p.name,
                Description: p.desc,
                Severity:    "high",
                CVSS:        8.0,
                Proof:       fmt.Sprintf("Pattern found: %s", p.pattern),
            })
        }
    }

    return vulns, nil
}

// إضافة وظائف مساعدة
func (ct *CustomTools) SetConcurrency(n int) {
	ct.concurrency = n
}

func (ct *CustomTools) SetTimeout(d time.Duration) {
	ct.timeout = d
}

func (ct *CustomTools) AddCustomTool(tool Tool) {
	ct.tools = append(ct.tools, tool)
}

// إضافة دوال تحليل جديدة
func parseJaelesOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Vulnerabilities []struct {
            Name        string `json:"name"`
            Severity    string `json:"severity"`
            Description string `json:"description"`
            Proof      string `json:"proof"`
        } `json:"vulnerabilities"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, v := range results.Vulnerabilities {
        vulns = append(vulns, Vulnerability{
            Name:        v.Name,
            Description: v.Description,
            Severity:    v.Severity,
            Proof:      v.Proof,
        })
    }

    return vulns, nil
}

func parseKatanaOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    
    // تحليل نتائج JavaScript
    if strings.Contains(output, "Sensitive Information Found") {
        vulns = append(vulns, Vulnerability{
            Name:        "JavaScript Information Disclosure",
            Description: "تم العثور على معلومات حساسة في ملفات JavaScript",
            Severity:    "medium",
        })
    }

    // تحليل نماذج الويب
    if strings.Contains(output, "Insecure Form") {
        vulns = append(vulns, Vulnerability{
            Name:        "Insecure Form Submission",
            Description: "نموذج غير آمن يرسل البيانات بدون HTTPS",
            Severity:    "high",
        })
    }

    return vulns, nil
}

func parseCloudSploitOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Findings []struct {
            Category    string `json:"category"`
            Description string `json:"description"`
            Risk       string `json:"risk"`
            Solution   string `json:"solution"`
        } `json:"findings"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, finding := range results.Findings {
        vulns = append(vulns, Vulnerability{
            Name:        fmt.Sprintf("Cloud Configuration Issue: %s", finding.Category),
            Description: finding.Description,
            Severity:    finding.Risk,
            Solution:    finding.Solution,
        })
    }

    return vulns, nil
}

func parseCRLFuzzOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    
    // تحليل نتائج CRLF Injection
    if strings.Contains(output, "CRLF Injection Found") {
        lines := strings.Split(output, "\n")
        for _, line := range lines {
            if strings.Contains(line, "URL:") {
                vulns = append(vulns, Vulnerability{
                    Name:        "CRLF Injection",
                    Description: "تم اكتشاف إمكانية حقن CRLF",
                    Severity:    "high",
                    URL:         strings.TrimSpace(strings.Split(line, "URL:")[1]),
                })
            }
        }
    }

    return vulns, nil
}

func parseGoSecOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Issues []struct {
            Severity    string `json:"severity"`
            Details     string `json:"details"`
            File       string `json:"file"`
            Line       int    `json:"line"`
            CWE        string `json:"cwe"`
        } `json:"Issues"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, issue := range results.Issues {
        vulns = append(vulns, Vulnerability{
            Name:        fmt.Sprintf("Security Issue in %s:%d", issue.File, issue.Line),
            Description: issue.Details,
            Severity:    issue.Severity,
            CVE:        issue.CWE,
        })
    }

    return vulns, nil
}

func parseInQLOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    
    // تحليل نتائج فحص GraphQL
    if strings.Contains(output, "Information Disclosure") {
        vulns = append(vulns, Vulnerability{
            Name:        "GraphQL Information Disclosure",
            Description: "تم اكتشاف تسريب معلومات من خلال GraphQL Introspection",
            Severity:    "medium",
            Type:        APIVulnerabilities,
        })
    }

    // فحص نقاط الضعف في المصادقة
    if strings.Contains(output, "Authentication Bypass") {
        vulns = append(vulns, Vulnerability{
            Name:        "GraphQL Authentication Bypass",
            Description: "إمكانية تجاوز المصادقة في GraphQL",
            Severity:    "critical",
            Type:        APIVulnerabilities,
        })
    }

    return vulns, nil
}

func parseTrivyOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Results []struct {
            Vulnerabilities []struct {
                VulnerabilityID string  `json:"VulnerabilityID"`
                PkgName        string  `json:"PkgName"`
                Severity       string  `json:"Severity"`
                Description    string  `json:"Description"`
                FixedVersion   string  `json:"FixedVersion"`
            } `json:"Vulnerabilities"`
        } `json:"Results"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, result := range results.Results {
        for _, vuln := range result.Vulnerabilities {
            vulns = append(vulns, Vulnerability{
                Name:        fmt.Sprintf("%s in %s", vuln.VulnerabilityID, vuln.PkgName),
                Description: vuln.Description,
                Severity:    vuln.Severity,
                Solution:    fmt.Sprintf("Upgrade to version %s", vuln.FixedVersion),
                Type:        UsingVulnerableComponents,
            })
        }
    }

    return vulns, nil
}

func parseTFSecOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Results []struct {
            RuleID      string `json:"rule_id"`
            Description string `json:"description"`
            Severity    string `json:"severity"`
            Location    struct {
                Filename string `json:"filename"`
                Line    int    `json:"line"`
            } `json:"location"`
        } `json:"results"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, result := range results.Results {
        vulns = append(vulns, Vulnerability{
            Name:        fmt.Sprintf("Infrastructure Issue: %s", result.RuleID),
            Description: result.Description,
            Severity:    result.Severity,
            Location:    fmt.Sprintf("%s:%d", result.Location.Filename, result.Location.Line),
            Type:        SecurityMisconfiguration,
        })
    }

    return vulns, nil
}

func parseGhauriOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    // تحليل نتائج SQL Injection المتقدمة
    if strings.Contains(output, "Payload Successfully Injected") {
        vulns = append(vulns, Vulnerability{
            Name:        "Advanced SQL Injection",
            Description: "تم اكتشاف نقطة ضعف حقن SQL متقدمة",
            Severity:    "critical",
            Type:        SQLInjection,
            CVSS:        9.0,
        })
    }

    // تحليل نتائج WAF Bypass
    if strings.Contains(output, "WAF Bypassed") {
        vulns = append(vulns, Vulnerability{
            Name:        "WAF Bypass Detected",
            Description: "تم اكتشاف إمكانية تجاوز جدار الحماية",
            Severity:    "high",
            Type:        SecurityMisconfiguration,
            CVSS:        8.0,
        })
    }

    return vulns, nil
}

func parseCorsyOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    // تحليل مشاكل CORS
    corsIssues := map[string]struct {
        desc     string
        severity string
    }{
        "Wildcard Origin": {
            desc:     "تم اكتشاف السماح لجميع المصادر في سياسة CORS",
            severity: "high",
        },
        "Credentials Allowed": {
            desc:     "تم اكتشاف السماح بإرسال بيانات المصادقة مع CORS",
            severity: "medium",
        },
    }

    for pattern, issue := range corsIssues {
        if strings.Contains(output, pattern) {
            vulns = append(vulns, Vulnerability{
                Name:        fmt.Sprintf("CORS Misconfiguration: %s", pattern),
                Description: issue.desc,
                Severity:    issue.severity,
                Type:        SecurityMisconfiguration,
            })
        }
    }

    return vulns, nil
}

func parseCloudMapperOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Findings []struct {
            Category    string `json:"category"`
            Description string `json:"description"`
            Risk       string `json:"risk"`
            Solution   string `json:"solution"`
        } `json:"findings"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, finding := range results.Findings {
        vulns = append(vulns, Vulnerability{
            Name:        fmt.Sprintf("Cloud Configuration Issue: %s", finding.Category),
            Description: finding.Description,
            Severity:    finding.Risk,
            Solution:    finding.Solution,
        })
    }

    return vulns, nil
}

func parseScoutSuiteOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Findings []struct {
            Category    string `json:"category"`
            Description string `json:"description"`
            Risk       string `json:"risk"`
            Solution   string `json:"solution"`
        } `json:"findings"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, finding := range results.Findings {
        vulns = append(vulns, Vulnerability{
            Name:        fmt.Sprintf("Cloud Configuration Issue: %s", finding.Category),
            Description: finding.Description,
            Severity:    finding.Risk,
            Solution:    finding.Solution,
        })
    }

    return vulns, nil
}

func parseKubescapeOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Controls []struct {
            ID          string `json:"id"`
            Name        string `json:"name"`
            Status      string `json:"status"`
            Severity    string `json:"severity"`
            Description string `json:"description"`
        } `json:"controls"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, control := range results.Controls {
        if control.Status == "failed" {
            vulns = append(vulns, Vulnerability{
                Name:        fmt.Sprintf("Kubernetes Security Issue: %s", control.Name),
                Description: control.Description,
                Severity:    control.Severity,
                Type:        SecurityMisconfiguration,
            })
        }
    }

    return vulns, nil
}

func parseCaidoOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Findings []struct {
            Category    string `json:"category"`
            Description string `json:"description"`
            Risk       string `json:"risk"`
            Solution   string `json:"solution"`
        } `json:"findings"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, finding := range results.Findings {
        vulns = append(vulns, Vulnerability{
            Name:        fmt.Sprintf("Cloud Configuration Issue: %s", finding.Category),
            Description: finding.Description,
            Severity:    finding.Risk,
            Solution:    finding.Solution,
        })
    }

    return vulns, nil
}

func parseJaelesCustomOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Vulnerabilities []struct {
            Name        string `json:"name"`
            Severity    string `json:"severity"`
            Description string `json:"description"`
            Proof      string `json:"proof"`
        } `json:"vulnerabilities"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, v := range results.Vulnerabilities {
        vulns = append(vulns, Vulnerability{
            Name:        v.Name,
            Description: v.Description,
            Severity:    v.Severity,
            Proof:      v.Proof,
        })
    }

    return vulns, nil
}

func parseMLScanOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    
    // فحص مشاكل أمان نماذج التعلم الآلي
    mlVulns := map[string]struct {
        desc     string
        severity string
        impact   string
    }{
        "Model Poisoning": {
            desc:     "إمكانية التلاعب بالنموذج من خلال بيانات التدريب",
            severity: "critical",
            impact:   "تأثير على دقة وموثوقية النموذج",
        },
        "Data Leakage": {
            desc:     "تسرب بيانات حساسة من خلال النموذج",
            severity: "high",
            impact:   "انتهاك خصوصية البيانات",
        },
        "Model Inversion": {
            desc:     "إمكانية استخراج بيانات التدريب من النموذج",
            severity: "high",
            impact:   "استرجاع البيانات الحساسة",
        },
    }

    for pattern, info := range mlVulns {
        if strings.Contains(output, pattern) {
            vulns = append(vulns, Vulnerability{
                Name:        fmt.Sprintf("ML Security Issue: %s", pattern),
                Description: info.desc,
                Severity:    info.severity,
                Impact:     info.impact,
                Type:       SecurityMisconfiguration,
            })
        }
    }

    return vulns, nil
}

func parseMythrilOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Issues []struct {
            Title       string `json:"title"`
            Description string `json:"description"`
            Severity    string `json:"severity"`
            SwcID      string `json:"swc-id"`
        } `json:"issues"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, issue := range results.Issues {
        vulns = append(vulns, Vulnerability{
            Name:        fmt.Sprintf("Smart Contract Vulnerability: %s", issue.Title),
            Description: issue.Description,
            Severity:    issue.Severity,
            CVE:        issue.SwcID,
            Type:        SecurityMisconfiguration,
        })
    }

    return vulns, nil
}

func parseAISecOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability

    // فحص مشاكل أمان الذكاء الاصطناعي
    aiVulns := map[string]struct {
        desc     string
        severity string
        impact   string
    }{
        "Prompt Injection": {
            desc:     "إمكانية التلاعب بالنموذج من خلال المدخلات",
            severity: "critical",
            impact:   "تنفيذ أوامر غير مصرح بها",
        },
        "Model Extraction": {
            desc:     "إمكانية استخراج معلومات عن النموذج",
            severity: "high",
            impact:   "سرقة الملكية الفكرية",
        },
        "Training Data Poisoning": {
            desc:     "تلوث بيانات التدريب",
            severity: "critical",
            impact:   "سلوك غير متوقع للنموذج",
        },
    }

    for pattern, info := range aiVulns {
        if strings.Contains(output, pattern) {
            vulns = append(vulns, Vulnerability{
                Name:        fmt.Sprintf("AI Security Issue: %s", pattern),
                Description: info.desc,
                Severity:    info.severity,
                Impact:     info.impact,
                Type:       SecurityMisconfiguration,
            })
        }
    }

    return vulns, nil
}

func parseSlitherOutput(output string) ([]Vulnerability, error) {
    var vulns []Vulnerability
    var results struct {
        Issues []struct {
            Title       string `json:"title"`
            Description string `json:"description"`
            Severity    string `json:"severity"`
            SwcID      string `json:"swc-id"`
        } `json:"issues"`
    }

    if err := json.Unmarshal([]byte(output), &results); err != nil {
        return nil, err
    }

    for _, issue := range results.Issues {
        vulns = append(vulns, Vulnerability{
            Name:        fmt.Sprintf("Smart Contract Vulnerability: %s", issue.Title),
            Description: issue.Description,
            Severity:    issue.Severity,
            CVE:        issue.SwcID,
            Type:        SecurityMisconfiguration,
        })
    }

    return vulns, nil
}
