# ماسح الثغرات الأمنية (Vulnerability Scanner)

أداة قوية مكتوبة بلغة Go لفحص وكشف الثغرات الأمنية في التطبيقات والأنظمة.

## المميزات الرئيسية

- فحص شامل للثغرات الأمنية
- تقارير مفصلة بصيغة HTML و JSON
- دعم لفحص نقاط النهاية API
- تتبع للمسح وسجلات التنفيذ
- واجهة سطر أوامر سهلة الاستخدام

## المتطلبات الأساسية

- Go 1.19 أو أحدث
- Git

## التثبيت

```bash
# استنساخ المستودع
git clone https://github.com/yourusername/vulne_scanner.git
cd vulne_scanner

# تثبيت الاعتماديات
go mod download

# بناء المشروع
go build -o vulne_scanner
```

## الاستخدام

```bash
# فحص موقع واحد
./vulne_scanner -target https://example.com

# فحص قائمة مواقع
./vulne_scanner -targets targets.txt

# تصدير التقرير بصيغة معينة
./vulne_scanner -target https://example.com -output report.html -format html
```

## المساهمة

نرحب بمساهماتكم! يرجى قراءة [دليل المساهمة](CONTRIBUTING.md) للمزيد من المعلومات.

## الرخصة

هذا المشروع مرخص تحت رخصة MIT - انظر ملف [LICENSE](LICENSE) للتفاصيل.

## الأمان

إذا اكتشفت ثغرة أمنية، يرجى اتباع إرشادات [الإبلاغ عن الثغرات الأمنية](SECURITY.md).
