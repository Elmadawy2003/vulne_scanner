package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config يمثل إعدادات البرنامج
type Config struct {
	Scanner struct {
		Timeout         time.Duration `yaml:"timeout"`
		ConcurrentScans int          `yaml:"concurrent_scans"`
		MaxDepth        int          `yaml:"max_depth"`
		UserAgent      string        `yaml:"user_agent"`

		EnabledChecks struct {
			XSS              bool `yaml:"xss"`
			SQLInjection     bool `yaml:"sql_injection"`
			OpenPorts        bool `yaml:"open_ports"`
			SSLTLS           bool `yaml:"ssl_tls"`
			DirectoryTraversal bool `yaml:"directory_traversal"`
			FileInclusion    bool `yaml:"file_inclusion"`
			CommandInjection bool `yaml:"command_injection"`
			InsecureHeaders  bool `yaml:"insecure_headers"`
		} `yaml:"enabled_checks"`

		Advanced struct {
			FollowRedirects bool          `yaml:"follow_redirects"`
			VerifySSL       bool          `yaml:"verify_ssl"`
			MaxRedirects    int           `yaml:"max_redirects"`
			RequestTimeout  time.Duration `yaml:"request_timeout"`
			RetryAttempts   int           `yaml:"retry_attempts"`
			RetryDelay      time.Duration `yaml:"retry_delay"`
		} `yaml:"advanced"`
	} `yaml:"scanner"`

	Reports struct {
		Formats []string `yaml:"formats"`
		IncludeDetails        bool     `yaml:"include_details"`
		IncludeRecommendations bool     `yaml:"include_recommendations"`
		SeverityLevels        []string `yaml:"severity_levels"`
	} `yaml:"reports"`

	Logging struct {
		Level      string `yaml:"level"`
		Format     string `yaml:"format"`
		Output     string `yaml:"output"`
		MaxSize    int    `yaml:"max_size"`
		MaxBackups int    `yaml:"max_backups"`
		MaxAge     int    `yaml:"max_age"`
		Compress   bool   `yaml:"compress"`
	} `yaml:"logging"`

	Security struct {
		RateLimit       int      `yaml:"rate_limit"`
		MaxPayloadSize  string   `yaml:"max_payload_size"`
		AllowedProtocols []string `yaml:"allowed_protocols"`
		BlockedIPs      []string `yaml:"blocked_ips"`
		APIKeys         map[string]string `yaml:"api_keys"`
	} `yaml:"security"`

	Alerts struct {
		Enabled  bool `yaml:"enabled"`
		Channels struct {
			Email struct {
				Enabled    bool     `yaml:"enabled"`
				SMTPServer string   `yaml:"smtp_server"`
				SMTPPort   int      `yaml:"smtp_port"`
				Username   string   `yaml:"username"`
				Password   string   `yaml:"password"`
				From       string   `yaml:"from"`
				To         []string `yaml:"to"`
			} `yaml:"email"`
			Slack struct {
				Enabled    bool   `yaml:"enabled"`
				WebhookURL string `yaml:"webhook_url"`
			} `yaml:"slack"`
			Telegram struct {
				Enabled  bool   `yaml:"enabled"`
				BotToken string `yaml:"bot_token"`
				ChatID   string `yaml:"chat_id"`
			} `yaml:"telegram"`
		} `yaml:"channels"`
	} `yaml:"alerts"`
}

// LoadConfig يقوم بتحميل الإعدادات من ملف
func LoadConfig(path string) (*Config, error) {
	// قراءة ملف الإعدادات
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("فشل في قراءة ملف الإعدادات: %v", err)
	}

	// تحليل الإعدادات
	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("فشل في تحليل ملف الإعدادات: %v", err)
	}

	// التحقق من صحة الإعدادات
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("إعدادات غير صالحة: %v", err)
	}

	// تحميل الإعدادات من متغيرات البيئة
	loadFromEnv(config)

	return config, nil
}

// validateConfig يتحقق من صحة الإعدادات
func validateConfig(cfg *Config) error {
	if cfg.Scanner.Timeout <= 0 {
		return fmt.Errorf("مهلة الفحص يجب أن تكون أكبر من صفر")
	}

	if cfg.Scanner.ConcurrentScans <= 0 {
		return fmt.Errorf("عدد العمليات المتزامنة يجب أن يكون أكبر من صفر")
	}

	if cfg.Scanner.MaxDepth <= 0 {
		return fmt.Errorf("عمق الفحص يجب أن يكون أكبر من صفر")
	}

	if cfg.Scanner.Advanced.MaxRedirects < 0 {
		return fmt.Errorf("الحد الأقصى لإعادة التوجيه يجب أن يكون صفر أو أكبر")
	}

	return nil
}

// loadFromEnv يحمل الإعدادات من متغيرات البيئة
func loadFromEnv(cfg *Config) {
	// تحميل مفاتيح API من متغيرات البيئة
	for key := range cfg.Security.APIKeys {
		envKey := fmt.Sprintf("VULNE_SCANNER_API_KEY_%s", key)
		if value := os.Getenv(envKey); value != "" {
			cfg.Security.APIKeys[key] = value
		}
	}

	// تحميل كلمات المرور من متغيرات البيئة
	if cfg.Alerts.Channels.Email.Enabled {
		if pass := os.Getenv("VULNE_SCANNER_SMTP_PASSWORD"); pass != "" {
			cfg.Alerts.Channels.Email.Password = pass
		}
	}

	if cfg.Alerts.Channels.Telegram.Enabled {
		if token := os.Getenv("VULNE_SCANNER_TELEGRAM_TOKEN"); token != "" {
			cfg.Alerts.Channels.Telegram.BotToken = token
		}
	}
}

// SaveConfig يحفظ الإعدادات في ملف
func SaveConfig(cfg *Config, path string) error {
	// تحويل الإعدادات إلى YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("فشل في تحويل الإعدادات: %v", err)
	}

	// حفظ الملف
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("فشل في حفظ ملف الإعدادات: %v", err)
	}

	return nil
}
