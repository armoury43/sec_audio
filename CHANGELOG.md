# Changelog

## v2.0.0
- Context-aware process and shell startup detection to reduce false positives.
- Added safer network visibility: TCP/UDP sockets, listeners, routes, interfaces, and DNS context where available.
- Unavailable Android/Termux capabilities are reported explicitly instead of being treated as safe findings.
- SSH authorized_keys output never prints public-key material; fingerprints are used when available.
- Executable-file checks use actual executable permissions rather than filename extensions alone.
- Hardened behavior under limited PATH and paths containing spaces.

# تاریخچه تغییرات (Changelog)

## [2.0.0] - 2026-09-04

### بهبودها
- تشخیص پردازش‌ها از حالت تطبیق ساده نام به امتیازدهی زمینه‌ای ارتقا یافت تا مواردی مثل `pdfminer` یا نام‌های عمومی بی‌دلیل مشکوک نشوند.
- تحلیل شبکه گسترده‌تر شد: اتصالات، listenerها، مسیر پیش‌فرض، رابط‌ها و DNS در صورت دسترسی گزارش می‌شوند.
- listenerهای بالقوه پرریسک فقط وقتی هشدار می‌شوند که روی آدرس غیرمحلی در دسترس باشند.
- بررسی فایل‌های اجرایی بر اساس permission واقعی انجام می‌شود، نه صرفاً پسوند فایل.
- تشخیص rc-file و cron برای جلوگیری از false positiveهای رایج مانند `lesspipe` و `dircolors` دقیق‌تر شد.
- وضعیت `UNAVAILABLE` از `SAFE` تفکیک شده و نتیجه نهایی ادعای امنیت قطعی نمی‌کند.


این پروژه از قالب [Keep a Changelog](https://keepachangelog.com/) پیروی می‌کند.

## [1.0.1] - 2026-09-04

### رفع‌شده (Fixed)
- **باگ self-matching در بخش «پردازش‌های مشکوک»**: فیلتر قبلی برای حذف
  خودِ فرآیند `grep` از نتایج، به عرض دقیق ستون `COMMAND` در خروجی `ps aux`
  وابسته بود و در برخی سیستم‌ها (وقتی خروجی truncate می‌شد) ممکن بود کار
  نکند و خودِ اسکریپت را به‌اشتباه «مشکوک» نشان دهد. با استفاده از
  «بریکت‌تریک» (`[m]iner` به‌جای `miner`) این وابستگی کاملاً حذف شد — بدون
  هیچ افت دقتی در شناسایی تهدیدهای واقعی (تست رگرسیون اضافه شد).

### افزوده‌شده (Added)
- بنر و پیش‌نمایش ترمینال (SVG) برای README.
- ۲ تست جدید (مجموعاً ۱۹ تست) شامل رگرسیون‌تست باگ بالا.

## [1.0.0] - 2026-09-04

### افزوده‌شده
- اسکریپت یکپارچه‌ی `security_audit.sh` با تشخیص خودکار محیط (لینوکس یا
  Termux).
- بررسی پردازش‌های مشکوک، اتصالات شبکه، فایل‌های اخیر/اجرایی/پنهان،
  کرون‌جاب‌ها، تغییرات `/etc` و rc-فایل‌ها، کلیدهای SSH، و بدافزارهای معروف.
- مجموعه تست خودکار (`tests/test_security_audit.sh`) با ۱۷ سناریوی تست.
- GitHub Actions CI برای ShellCheck، بررسی سینتکس، و اجرای تست‌ها روی هر
  push/PR.
- مستندات کامل: README، راهنمای رفع مشکلات (remediation guide)، سیاست
  امنیتی، و راهنمای مشارکت.

### امنیت (Hardening)
- فایل گزارش با دسترسی `600` ساخته می‌شود.
- کلید عمومی SSH به‌طور کامل چاپ نمی‌شود؛ فقط نوع/کامنت/اثرانگشت.
- تمام متغیرها quote شده‌اند (مقاوم در برابر تزریق از طریق نام فایل).
- بدون استفاده از `eval`.
- جستجوهای سنگین با `timeout` محدود شده‌اند.
- `set -u` برای تشخیص زودهنگام باگ‌های ناشی از متغیر تعریف‌نشده.
