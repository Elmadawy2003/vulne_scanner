package scanning

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// PortScanner وحدة فحص المنافذ المفتوحة
type PortScanner struct {
	timeout    time.Duration
	concurrent int
}

// CommonPorts قائمة المنافذ الشائعة للفحص
var CommonPorts = []int{
	21,   // FTP
	22,   // SSH
	23,   // Telnet
	25,   // SMTP
	53,   // DNS
	80,   // HTTP
	110,  // POP3
	111,  // RPC
	135,  // RPC
	139,  // NetBIOS
	143,  // IMAP
	443,  // HTTPS
	445,  // SMB
	993,  // IMAPS
	995,  // POP3S
	1433, // MSSQL
	1521, // Oracle
	3306, // MySQL
	3389, // RDP
	5432, // PostgreSQL
	5900, // VNC
	6379, // Redis
	8080, // HTTP Proxy
	8443, // HTTPS Alt
	27017, // MongoDB
}

// ServiceNames أسماء الخدمات المعروفة
var ServiceNames = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPC",
	135:   "RPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	27017: "MongoDB",
}

// NewPortScanner ينشئ فاحص منافذ جديد
func NewPortScanner(timeout time.Duration, concurrent int) *PortScanner {
	return &PortScanner{
		timeout:    timeout,
		concurrent: concurrent,
	}
}

// ScanHost يفحص المنافذ المفتوحة على مضيف معين
func (s *PortScanner) ScanHost(ctx context.Context, host string) ([]Vulnerability, error) {
	// التحقق من صحة المضيف
	if net.ParseIP(host) == nil {
		// إذا لم يكن عنوان IP، نحاول الحصول على IP
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("فشل في حل اسم المضيف: %v", err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("لم يتم العثور على عنوان IP للمضيف: %s", host)
		}
		host = ips[0].String()
	}

	var vulnerabilities []Vulnerability
	portChan := make(chan int, len(CommonPorts))
	resultChan := make(chan *Vulnerability, len(CommonPorts))
	var wg sync.WaitGroup

	// إنشاء العمال
	for i := 0; i < s.concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				select {
				case <-ctx.Done():
					return
				default:
					if vuln := s.scanPort(ctx, host, port); vuln != nil {
						resultChan <- vuln
					}
				}
			}
		}()
	}

	// إرسال المنافذ للفحص
	go func() {
		for _, port := range CommonPorts {
			portChan <- port
		}
		close(portChan)
	}()

	// انتظار اكتمال العمال
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// جمع النتائج
	for vuln := range resultChan {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities, nil
}

// scanPort يفحص منفذ واحد
func (s *PortScanner) scanPort(ctx context.Context, host string, port int) *Vulnerability {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	
	// إنشاء موقت للفحص
	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	// محاولة الاتصال
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// المنفذ مفتوح، إنشاء ثغرة
	serviceName := ServiceNames[port]
	if serviceName == "" {
		serviceName = fmt.Sprintf("Unknown-%d", port)
	}

	severity := s.determineSeverity(port, serviceName)
	description := fmt.Sprintf("تم اكتشاف منفذ مفتوح: %d (%s)", port, serviceName)
	
	return &Vulnerability{
		Type:        VulnTypeOpenPort,
		Severity:    severity,
		Description: description,
		Evidence:    fmt.Sprintf("المنفذ %d مفتوح ويستمع للاتصالات", port),
		Solution:    "تحقق من ضرورة فتح هذا المنفذ وقم بتقييد الوصول إليه إذا لم يكن ضرورياً",
		CVSS:        s.calculateCVSS(port, serviceName),
		References: []string{
			"https://www.speedguide.net/ports.php",
			fmt.Sprintf("https://www.speedguide.net/port.php?port=%d", port),
		},
		Location: target,
	}
}

// determineSeverity يحدد مستوى خطورة المنفذ المفتوح
func (s *PortScanner) determineSeverity(port int, service string) string {
	// المنافذ عالية الخطورة
	highRiskPorts := map[int]bool{
		21:   true, // FTP
		23:   true, // Telnet
		445:  true, // SMB
		3389: true, // RDP
	}

	// المنافذ متوسطة الخطورة
	mediumRiskPorts := map[int]bool{
		22:    true, // SSH
		3306:  true, // MySQL
		5432:  true, // PostgreSQL
		27017: true, // MongoDB
	}

	if highRiskPorts[port] {
		return SeverityHigh
	}
	if mediumRiskPorts[port] {
		return SeverityMedium
	}
	return SeverityLow
}

// calculateCVSS يحسب درجة CVSS للمنفذ المفتوح
func (s *PortScanner) calculateCVSS(port int, service string) float64 {
	// المنافذ عالية الخطورة
	highRiskPorts := map[int]float64{
		21:   7.5, // FTP
		23:   8.0, // Telnet
		445:  8.5, // SMB
		3389: 8.0, // RDP
	}

	// المنافذ متوسطة الخطورة
	mediumRiskPorts := map[int]float64{
		22:    5.5, // SSH
		3306:  6.0, // MySQL
		5432:  6.0, // PostgreSQL
		27017: 6.0, // MongoDB
	}

	if score, exists := highRiskPorts[port]; exists {
		return score
	}
	if score, exists := mediumRiskPorts[port]; exists {
		return score
	}
	return 4.0 // درجة افتراضية للمنافذ الأخرى
} 