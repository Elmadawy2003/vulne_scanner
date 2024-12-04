package scanning

import (
	"context"
	"vulne_scanner/types"
)

// Tool واجهة لأدوات الفحص
type Tool interface {
	// Name يعيد اسم الأداة
	Name() string

	// Description يعيد وصف الأداة
	Description() string

	// Run يشغل الأداة على الهدف المحدد
	Run(ctx context.Context, target string) ([]types.Vulnerability, error)

	// Stop يوقف الأداة
	Stop()

	// GetProgress يعيد نسبة تقدم الأداة
	GetProgress() float64
} 