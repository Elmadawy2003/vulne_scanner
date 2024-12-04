package scanning

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// SSLScanner وحدة فحص SSL/TLS
type SSLScanner struct {
	timeout time.Duration
}

// WeakCiphers قائمة بالتشفيرات الضعيفة
var WeakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:          "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:         "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:       "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
}

// WeakProtocols قائمة بالبروتوكولات الضعيفة
var WeakProtocols = map[uint16]string{
	tls.VersionSSL30: "SSLv3",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
}

// NewSSLScanner ينشئ فاحص SSL/TLS جديد
func NewSSLScanner(timeout time.Duration) *SSLScanner {
	return &SSLScanner{
		timeout: timeout,
	}
}

// ScanHost يفحص إعدادات SSL/TLS للمضيف
func (s *SSLScanner) ScanHost(ctx context.Context, host string) (*Vulnerability, error) {
	// التأكد من وجود رقم المنفذ
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// إنشاء اتصال TCP
	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	// فحص البروتوكولات والتشفيرات المدعومة
	var vulnerabilities []string
	var evidence []string

	// فحص كل بروتوكول
	for version := range WeakProtocols {
		conn, err := dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, fmt.Errorf("فشل الاتصال بالمضيف: %v", err)
		}

		config := &tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			InsecureSkipVerify: true,
		}

		tlsConn := tls.Client(conn, config)
		err = tlsConn.HandshakeContext(ctx)
		tlsConn.Close()
		conn.Close()

		if err == nil {
			vulnerabilities = append(vulnerabilities,
				fmt.Sprintf("يدعم الخادم بروتوكول %s الضعيف", WeakProtocols[version]))
			evidence = append(evidence,
				fmt.Sprintf("تم إنشاء اتصال ناجح باستخدام %s", WeakProtocols[version]))
		}
	}

	// فحص الشهادة
	certIssues := s.checkCertificate(ctx, host)
	if len(certIssues) > 0 {
		vulnerabilities = append(vulnerabilities, certIssues...)
	}

	// إذا تم اكتشاف أي ضعف
	if len(vulnerabilities) > 0 {
		return &Vulnerability{
			Type:        VulnTypeSSLTLS,
			Severity:    s.determineSeverity(vulnerabilities),
			Description: "تم اكتشاف مشاكل في إعدادات SSL/TLS",
			Evidence:    strings.Join(evidence, "\n"),
			Solution: `1. تعطيل البروتوكولات القديمة (SSLv3, TLS 1.0, TLS 1.1)
2. تعطيل التشفيرات الضعيفة
3. تحديث شهادة SSL/TLS
4. تكوين Perfect Forward Secrecy
5. تفعيل HSTS`,
			CVSS: s.calculateCVSS(vulnerabilities),
			References: []string{
				"https://www.ssllabs.com/ssl-pulse/",
				"https://www.acunetix.com/vulnerabilities/web/tls-ssl-protocol-vulnerability/",
				"https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet",
			},
			Location: host,
		}, nil
	}

	return nil, nil
}

// checkCertificate يفحص شهادة SSL/TLS
func (s *SSLScanner) checkCertificate(ctx context.Context, host string) []string {
	var issues []string

	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return []string{fmt.Sprintf("فشل في فحص الشهادة: %v", err)}
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	now := time.Now()

	// التحقق من تاريخ انتهاء الصلاحية
	if now.After(cert.NotAfter) {
		issues = append(issues, "الشهادة منتهية الصلاحية")
	}

	// التحقق من تاريخ بدء الصلاحية
	if now.Before(cert.NotBefore) {
		issues = append(issues, "الشهادة غير صالحة بعد")
	}

	// التحقق من قرب انتهاء الصلاحية
	if cert.NotAfter.Sub(now) < (30 * 24 * time.Hour) {
		issues = append(issues, "الشهادة ستنتهي صلاحيتها قريباً (أقل من 30 يوم)")
	}

	// التحقق من خوارزمية التوقيع
	switch cert.SignatureAlgorithm {
	case tls.SHA1WithRSA, tls.DSAWithSHA1, tls.ECDSAWithSHA1:
		issues = append(issues, "الشهادة تستخدم خوارزمية توقيع ضعيفة (SHA1)")
	}

	// التحقق من طول المفتاح
	if publicKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		keyLength := publicKey.N.BitLen()
		if keyLength < 2048 {
			issues = append(issues, fmt.Sprintf("طول مفتاح RSA ضعيف (%d bits)", keyLength))
		}
	}

	return issues
}

// determineSeverity يحدد مستوى خطورة المشاكل المكتشفة
func (s *SSLScanner) determineSeverity(issues []string) string {
	for _, issue := range issues {
		// المشاكل عالية الخطورة
		if strings.Contains(issue, "منتهية الصلاحية") ||
			strings.Contains(issue, "SHA1") ||
			strings.Contains(issue, "SSLv3") {
			return SeverityHigh
		}
	}

	// المشاكل متوسطة الخطورة
	for _, issue := range issues {
		if strings.Contains(issue, "TLS 1.0") ||
			strings.Contains(issue, "ستنتهي صلاحيتها قريباً") {
			return SeverityMedium
		}
	}

	return SeverityLow
}

// calculateCVSS يحسب درجة CVSS للمشاكل المكتشفة
func (s *SSLScanner) calculateCVSS(issues []string) float64 {
	var maxScore float64

	for _, issue := range issues {
		var score float64

		switch {
		case strings.Contains(issue, "منتهية الصلاحية"):
			score = 7.5
		case strings.Contains(issue, "SHA1"):
			score = 7.0
		case strings.Contains(issue, "SSLv3"):
			score = 6.8
		case strings.Contains(issue, "TLS 1.0"):
			score = 5.5
		case strings.Contains(issue, "ستنتهي صلاحيتها قريباً"):
			score = 4.0
		default:
			score = 3.0
		}

		if score > maxScore {
			maxScore = score
		}
	}

	return maxScore
} 