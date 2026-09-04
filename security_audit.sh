#!/usr/bin/env bash
###############################################################################
# security_audit.sh  —  ابزار واحد بررسی امنیتی
# پشتیبانی از: لینوکس (Ubuntu/Debian) و Termux (اندروید)
#
# این ابزار فقط بررسی و گزارش‌دهی می‌کند. هیچ فایل/پردازش/کرون‌جابی را
# بدون تأیید صریح کاربر حذف یا تغییر نمی‌دهد.
#
# نکات امنیتیِ خودِ اسکریپت (Hardening):
#  - تمام متغیرها quote شده‌اند تا از word-splitting / glob expansion جلوگیری شود.
#  - از eval یا اجرای مستقیم داده‌ی خارجی به‌عنوان کد استفاده نشده است.
#  - فایل گزارش با دسترسی 600 (فقط خودِ کاربر) ساخته می‌شود تا اطلاعات حساس
#    (پردازش‌ها، اتصالات شبکه، اثر انگشت کلید SSH) در دسترس کاربران دیگر سیستم نباشد.
#  - به‌جای چاپ کامل محتوای authorized_keys، فقط نوع کلید، کامنت و اثرانگشت
#    (fingerprint) نمایش داده می‌شود تا خودِ کلید عمومی به‌طور کامل در لاگ/ترمینال
#    ذخیره نشود.
#  - جستجوهای سنگین (مثل find روی کل فایل‌سیستم) با timeout محدود می‌شوند تا
#    اسکریپت هنگ نکند یا منابع را قفل نکند.
#  - `set -u` فعال است تا استفاده از متغیر تعریف‌نشده بلافاصله خطا بدهد
#    (باگ‌های احتمالی در خودِ اسکریپت زودتر پیدا می‌شوند).
#  - `set -e` عمداً فعال *نیست*، چون بسیاری از دستورات بررسی (grep/find) وقتی
#    چیزی پیدا نمی‌کنند exit code غیرصفر برمی‌گردانند؛ به‌جایش هر بلوک بحرانی
#    خودش خطا را کنترل می‌کند.
###############################################################################

set -uo pipefail

# ---------- رنگ‌ها ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ISSUES_FOUND=0
CHECKS_UNAVAILABLE=0
SCRIPT_VERSION="1.0.2"

# ---------- تشخیص محیط اجرا (Termux یا لینوکس معمولی) ----------
IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=1
fi

HOME_DIR="${HOME:-$(pwd)}"

if [ "$IS_TERMUX" -eq 1 ]; then
    REPORT_FILE="${HOME_DIR}/security_report_termux_$(date +%Y%m%d_%H%M%S).txt"
else
    REPORT_FILE="${HOME_DIR}/security_report_$(date +%Y%m%d_%H%M%S).txt"
fi

# ساخت فایل گزارش با دسترسی محدود از همان ابتدا (قبل از نوشتن هر داده‌ای)
( umask 077 && : > "$REPORT_FILE" ) || {
    echo "خطا: امکان ساخت فایل گزارش در $REPORT_FILE وجود ندارد." >&2
    exit 1
}
chmod 600 "$REPORT_FILE" 2>/dev/null || true

# ---------- توابع کمکی ----------
log_plain() {
    # چاپ رنگی روی صفحه + نسخه‌ی بدون کد رنگ در فایل گزارش
    printf '%b\n' "$1"
    printf '%b\n' "$1" | sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g' >> "$REPORT_FILE"
}

flag() {
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    log_plain "${RED}${BOLD}[⚠ مشکوک]${NC} $1"
}

ok() {
    log_plain "${GREEN}[✓ سالم]${NC} $1"
}

info() {
    log_plain "${YELLOW}$1${NC}"
}

unavailable() {
    CHECKS_UNAVAILABLE=$((CHECKS_UNAVAILABLE + 1))
    log_plain "${YELLOW}[⚠ در دسترس نیست]${NC} $1"
}

section() {
    log_plain ""
    log_plain "${BLUE}${BOLD}============================================================${NC}"
    log_plain "${BLUE}${BOLD}  $1${NC}"
    log_plain "${BLUE}${BOLD}============================================================${NC}"
}

# اجرای امن یک دستور با محدودیت زمانی (در صورت وجود timeout)
safe_run() {
    # $1 = مهلت به ثانیه ، بقیه‌ی آرگومان‌ها = دستور
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@" 2>/dev/null
    else
        "$@" 2>/dev/null
    fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

###############################################################################
# شروع گزارش
###############################################################################
log_plain "${CYAN}${BOLD}=== ابزار بررسی امنیتی سیستم — نسخه ${SCRIPT_VERSION} ===${NC}"
log_plain "${CYAN}تاریخ: $(date)${NC}"
log_plain "${CYAN}محیط: $([ "$IS_TERMUX" -eq 1 ] && echo "Termux (Android)" || echo "Linux")   کاربر: $(whoami 2>/dev/null || id -un)${NC}"

if [ "$IS_TERMUX" -eq 0 ] && [ "${EUID:-$(id -u)}" -ne 0 ]; then
    info "توجه: بدون sudo اجرا شده. برخی بررسی‌ها (کرون‌جاب روت، کل /etc) ناقص خواهند بود."
    info "برای گزارش کامل‌تر: sudo bash $0"
fi

###############################################################################
# 1. پردازش‌های مشکوک
###############################################################################
section "1) پردازش‌های مشکوک"

# نکته‌ی مهم (رفع باگ): از "بریکت‌تریک" ([r]andom به‌جای random) استفاده شده
# تا خودِ فرآیند grep در حال اجرا اشتباهاً به‌عنوان پردازش مشکوک تشخیص داده
# نشود. فیلتر قبلی (grep -v 'grep -Ei') به عرض ستون COMMAND در `ps aux`
# وابسته بود و در برخی سیستم‌ها که خروجی غیر-tty را truncate می‌کنند ممکن
# بود کار نکند؛ بریکت‌تریک این وابستگی را کاملاً حذف می‌کند.
SUSPICIOUS_RE='[r]andom|[c]rypto|[m]iner|[h]idden|[x]mrig|[k]insing|[k]devtmpfsi|[c]ryptonight'

FOUND_PROC="$(ps aux 2>/dev/null | grep -Ei -- "$SUSPICIOUS_RE")"
if [ -n "$FOUND_PROC" ]; then
    flag "پردازش(های) با نام مشکوک:"
    log_plain "$FOUND_PROC"
else
    ok "پردازش با نام مشکوک پیدا نشد."
fi

log_plain ""
log_plain "${BOLD}-- پردازش‌های اجراشده از /tmp یا /dev/shm --${NC}"
TMP_PROC="$(ls -l /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm' || true)"
if [ -n "$TMP_PROC" ]; then
    flag "پردازش با فایل اجرایی در /tmp یا /dev/shm:"
    log_plain "$TMP_PROC"
else
    ok "پردازشی از /tmp یا /dev/shm اجرا نمی‌شود (یا دسترسی کافی برای بررسی /proc نیست)."
fi

log_plain ""
log_plain "${BOLD}-- مصرف بالای CPU/RAM (بالای ۵۰٪) --${NC}"
HIGH_USAGE="$(ps aux 2>/dev/null | awk '$3+0 > 50 || $4+0 > 50 {print}' | grep -v 'COMMAND$' || true)"
if [ -n "$HIGH_USAGE" ]; then
    flag "پردازش‌های با مصرف بالای منابع:"
    log_plain "$HIGH_USAGE"
else
    ok "پردازشی با مصرف غیرعادی CPU/RAM دیده نشد."
fi

###############################################################################
# 2. اتصالات شبکه
###############################################################################
section "2) اتصالات شبکه"

NET_OUT=""
if has_cmd ss; then
    NET_OUT="$(safe_run 10 ss -tulpn)"
elif has_cmd netstat; then
    NET_OUT="$(safe_run 10 netstat -tulpn)"
fi

if [ -n "$NET_OUT" ]; then
    log_plain "${BOLD}-- تمام اتصالات فعال --${NC}"
    log_plain "$NET_OUT"

    log_plain ""
    ESTABLISHED="$(printf '%s\n' "$NET_OUT" | grep -i 'ESTAB' || true)"
    if [ -n "$ESTABLISHED" ]; then
        log_plain "اتصالات برقرار (ESTABLISHED):"
        log_plain "$ESTABLISHED"
        info "اتصال برقرار به‌تنهایی نشانه بدافزار نیست؛ مقصدها را بررسی کنید."
    else
        ok "اتصال برقرار مشکوکی دیده نشد."
    fi

    log_plain ""
    LISTENING="$(printf '%s\n' "$NET_OUT" | grep -i 'LISTEN' || true)"
    log_plain "${BOLD}-- پورت‌های در حال گوش‌دادن --${NC}"
    log_plain "$LISTENING"
    info "پورت‌های ناشناخته‌ای که خودتان باز نکرده‌اید را بررسی کنید."
else
    unavailable "ابزار ss/netstat در این محیط در دسترس نیست؛ بررسی اتصالات شبکه کامل انجام نشد. در Termux می‌توانید net-tools نصب کنید."
fi

###############################################################################
# 3. فایل‌های اخیر و مشکوک
###############################################################################
section "3) فایل‌های اخیر و مشکوک"

if [ "$IS_TERMUX" -eq 1 ]; then
    DOWNLOAD_DIR="${HOME_DIR}/storage/downloads"
else
    DOWNLOAD_DIR="${HOME_DIR}/Downloads"
fi

if [ -d "$DOWNLOAD_DIR" ]; then
    RECENT_FILES="$(find "$DOWNLOAD_DIR" -type f -mtime -1 2>/dev/null)"
    log_plain "${BOLD}-- فایل‌های دانلود شده در ۲۴ ساعت اخیر ($DOWNLOAD_DIR) --${NC}"
    if [ -n "$RECENT_FILES" ]; then
        log_plain "$RECENT_FILES"
    else
        log_plain "فایل جدیدی پیدا نشد."
    fi
else
    info "مسیر $DOWNLOAD_DIR وجود ندارد (در Termux با termux-setup-storage بسازید)."
fi

if [ "$IS_TERMUX" -eq 0 ] && [ -d /tmp ]; then
    RECENT_TMP="$(find /tmp -type f -mtime -1 2>/dev/null)"
    if [ -n "$RECENT_TMP" ]; then
        log_plain ""
        log_plain "${BOLD}-- فایل‌های اخیر در /tmp --${NC}"
        log_plain "$RECENT_TMP"
    fi
fi

log_plain ""
log_plain "${BOLD}-- فایل‌های اجرایی مشکوک (۷ روز اخیر) --${NC}"
EXEC_SEARCH_DIRS=("$DOWNLOAD_DIR")
[ "$IS_TERMUX" -eq 0 ] && EXEC_SEARCH_DIRS+=("/tmp" "/dev/shm")
EXEC_FILES=""
for d in "${EXEC_SEARCH_DIRS[@]}"; do
    [ -d "$d" ] || continue
    found="$(find "$d" -type f \( -iname '*.sh' -o -iname '*.bin' -o -iname '*.py' -o -iname '*.exe' -o -iname '*.elf' \) -mtime -7 2>/dev/null)"
    [ -n "$found" ] && EXEC_FILES="${EXEC_FILES}${found}"$'\n'
done
if [ -n "${EXEC_FILES//[$'\n\t ']/}" ]; then
    flag "فایل‌های اجرایی اخیر:"
    log_plain "$EXEC_FILES"
else
    ok "فایل اجرایی مشکوکی پیدا نشد."
fi

log_plain ""
log_plain "${BOLD}-- فایل‌های پنهان در دایرکتوری هوم --${NC}"
HIDDEN_FILES="$(find "$HOME_DIR" -maxdepth 1 -name '.*' -type f 2>/dev/null)"
log_plain "$HIDDEN_FILES"
info "فایل‌های پنهان با نام تصادفی یا عجیب را بررسی کنید."

###############################################################################
# 4. کرون‌جاب‌ها
###############################################################################
section "4) کرون‌جاب‌ها"

log_plain "${BOLD}-- کرون‌جاب کاربر فعلی --${NC}"
if has_cmd crontab; then
    USER_CRON="$(crontab -l 2>/dev/null)"
    if [ -n "$USER_CRON" ]; then
        log_plain "$USER_CRON"
        SUSPICIOUS_CRON="$(printf '%s\n' "$USER_CRON" | grep -Ei 'curl|wget|/tmp/|http://|\.sh' || true)"
        if [ -n "$SUSPICIOUS_CRON" ]; then
            flag "کرون‌جاب مشکوک (دانلود/اجرای فایل خارجی):"
            log_plain "$SUSPICIOUS_CRON"
        fi
    else
        log_plain "کرون‌جابی تعریف نشده."
    fi
else
    info "دستور crontab در دسترس نیست."
fi

if [ "$IS_TERMUX" -eq 0 ]; then
    log_plain ""
    log_plain "${BOLD}-- کرون‌جاب روت و فایل‌های کرون سیستمی --${NC}"
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        safe_run 5 crontab -u root -l
        for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly; do
            [ -d "$d" ] && log_plain "$(ls -la "$d" 2>/dev/null)"
        done
    else
        info "برای بررسی کرون‌جاب روت با sudo اجرا کنید."
    fi
fi

###############################################################################
# 5. تغییرات اخیر سیستم
###############################################################################
section "5) تغییرات اخیر سیستم"

if [ "$IS_TERMUX" -eq 0 ]; then
    log_plain "${BOLD}-- فایل‌های تغییر یافته در /etc (۷ روز اخیر) --${NC}"
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        ETC_CHANGES="$(safe_run 15 find /etc -type f -mtime -7)"
        log_plain "${ETC_CHANGES:-موردی پیدا نشد.}"
    else
        info "برای بررسی کامل /etc نیاز به sudo دارید."
    fi
fi

log_plain ""
log_plain "${BOLD}-- بررسی فایل‌های راه‌انداز شل (rc files) --${NC}"
RC_FILES=("${HOME_DIR}/.bashrc" "${HOME_DIR}/.profile" "${HOME_DIR}/.bash_aliases" "${HOME_DIR}/.zshrc")
for f in "${RC_FILES[@]}"; do
    [ -f "$f" ] || continue
    MTIME="$(stat -c '%y' "$f" 2>/dev/null || stat -f '%Sm' "$f" 2>/dev/null)"
    log_plain "$f  -->  آخرین تغییر: $MTIME"
    SUS_LINE="$(grep -Ei 'curl|wget|base64 -d|eval|nc -e|/tmp/' "$f" 2>/dev/null || true)"
    if [ -n "$SUS_LINE" ]; then
        flag "خط مشکوک در $f:"
        log_plain "$SUS_LINE"
    fi
done

###############################################################################
# 6. بررسی SSH
###############################################################################
section "6) بررسی SSH"

SSH_DIR="${HOME_DIR}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"
if [ -f "$AUTH_KEYS" ]; then
    log_plain "${BOLD}-- کلیدهای مجاز SSH (فقط نوع/کامنت/اثرانگشت نمایش داده می‌شود) --${NC}"
    # به‌جای چاپ کامل کلید عمومی، فقط نوع، اثرانگشت و کامنت نشان داده می‌شود
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        if has_cmd ssh-keygen; then
            FP="$(printf '%s\n' "$line" | ssh-keygen -lf /dev/stdin 2>/dev/null)"
            log_plain "${FP:-$(printf '%s' "$line" | cut -c1-60)...(نامعتبر یا فرمت ناشناخته)}"
        else
            KEY_TYPE="$(printf '%s\n' "$line" | awk '{print $1}')"
            COMMENT="$(printf '%s\n' "$line" | awk '{print $NF}')"
            log_plain "نوع: $KEY_TYPE   کامنت: $COMMENT"
        fi
    done < "$AUTH_KEYS"
    info "هر کلیدی که خودتان اضافه نکرده‌اید را فوراً از authorized_keys حذف کنید."
else
    ok "فایل authorized_keys وجود ندارد."
fi

if [ -f "${SSH_DIR}/known_hosts" ]; then
    log_plain ""
    KH_COUNT="$(wc -l < "${SSH_DIR}/known_hosts" 2>/dev/null)"
    log_plain "${BOLD}-- known_hosts --${NC}  تعداد هاست ثبت‌شده: ${KH_COUNT:-0}"
fi

###############################################################################
# 7. جستجوی بدافزارهای معروف
###############################################################################
section "7) جستجوی بدافزارهای شناخته‌شده"

MALWARE_PATTERNS=("*kdevtmpfsi*" "*kinsing*" "*xmrig*" "*miner*" "*cryptonight*")

if [ "$IS_TERMUX" -eq 0 ]; then
    log_plain "${BOLD}-- جستجو در فایل‌سیستم (حداکثر ۲۰ ثانیه، ممکن است ناقص باشد) --${NC}"
    FIND_ARGS=()
    for i in "${!MALWARE_PATTERNS[@]}"; do
        [ "$i" -gt 0 ] && FIND_ARGS+=(-o)
        FIND_ARGS+=(-iname "${MALWARE_PATTERNS[$i]}")
    done
    MALWARE_FILES="$(safe_run 20 find / -xdev \( "${FIND_ARGS[@]}" \))"
    if [ -n "$MALWARE_FILES" ]; then
        flag "فایل‌های مشکوک به بدافزار معروف:"
        log_plain "$MALWARE_FILES"
    else
        ok "اثری از بدافزارهای معروف در جستجوی محدود پیدا نشد."
    fi

    log_plain ""
    log_plain "${BOLD}-- فایل‌های مخفی با نام تصادفی در /tmp، /dev/shm --${NC}"
    RANDOM_TMP=""
    for d in /tmp /dev/shm; do
        [ -d "$d" ] || continue
        f="$(find "$d" -maxdepth 1 -type f -regextype posix-extended -regex '.*/\.[a-zA-Z0-9]{6,}$' 2>/dev/null)"
        [ -n "$f" ] && RANDOM_TMP="${RANDOM_TMP}${f}"$'\n'
    done
    if [ -n "${RANDOM_TMP//[$'\n\t ']/}" ]; then
        flag "فایل مخفی با نام تصادفی پیدا شد:"
        log_plain "$RANDOM_TMP"
    else
        ok "فایل مخفی با نام تصادفی پیدا نشد."
    fi
else
    unavailable "در Termux جستجوی کل فایل‌سیستم انجام نمی‌شود (محدودیت دسترسی اندروید). فقط مسیرهای قابل‌دسترسی Termux بررسی می‌شوند."
fi

###############################################################################
# 8. مخصوص Termux: تاریخچه دستورات و پکیج‌های اندروید
###############################################################################
if [ "$IS_TERMUX" -eq 1 ]; then
    section "8) تاریخچه دستورات Termux"
    HIST_FILE="${HOME_DIR}/.bash_history"
    if [ -f "$HIST_FILE" ]; then
        log_plain "${BOLD}-- ۲۰ دستور آخر --${NC}"
        tail -20 "$HIST_FILE" 2>/dev/null | while IFS= read -r l; do log_plain "$l"; done
        SUS_HIST="$(grep -Ei 'curl|wget|base64 -d|chmod \+x.*tmp|nc -e' "$HIST_FILE" 2>/dev/null || true)"
        if [ -n "$SUS_HIST" ]; then
            flag "دستورات مشکوک در تاریخچه:"
            log_plain "$SUS_HIST"
        fi
    else
        log_plain "فایل تاریخچه پیدا نشد."
    fi

    section "9) برنامه‌های نصب‌شده روی اندروید"
    if has_cmd pm; then
        log_plain "${BOLD}-- پکیج‌های نصب‌شده توسط کاربر --${NC}"
        PM_OUT="$(safe_run 10 pm list packages -3)"
        PM_STATUS=$?
        if [ "$PM_STATUS" -eq 0 ] && [ -n "$PM_OUT" ]; then
            log_plain "$PM_OUT"
            info "پکیج‌های ناشناخته یا با نام تصادفی را بررسی کنید."
        else
            unavailable "دریافت فهرست پکیج‌های اندروید با pm در این محیط موفق نشد؛ خروجی به‌عنوان نتیجه امنیتی تفسیر نمی‌شود."
        fi
    else
        unavailable "دستور pm در این محیط در دسترس نیست؛ بررسی پکیج‌های اندروید انجام نشد."
    fi
fi

###############################################################################
# خلاصه نهایی
###############################################################################
section "خلاصه نهایی"

if [ "$ISSUES_FOUND" -eq 0 ] && [ "$CHECKS_UNAVAILABLE" -eq 0 ]; then
    log_plain "${GREEN}${BOLD}✔ در بررسی‌های انجام‌شده مورد مشکوکی پیدا نشد.${NC}"
elif [ "$ISSUES_FOUND" -eq 0 ] && [ "$CHECKS_UNAVAILABLE" -gt 0 ]; then
    log_plain "${YELLOW}${BOLD}⚠ در بررسی‌های انجام‌شده مورد مشکوکی پیدا نشد، اما ${CHECKS_UNAVAILABLE} بررسی در این محیط کامل/قابل‌اجرا نبود.${NC}"
elif [ "$CHECKS_UNAVAILABLE" -eq 0 ]; then
    log_plain "${RED}${BOLD}⚠ تعداد ${ISSUES_FOUND} مورد مشکوک پیدا شد. موارد بالا را بررسی کنید.${NC}"
else
    log_plain "${RED}${BOLD}⚠ تعداد ${ISSUES_FOUND} مورد مشکوک پیدا شد؛ ${CHECKS_UNAVAILABLE} بررسی نیز کامل/قابل‌اجرا نبود.${NC}"
fi

log_plain ""
log_plain "${CYAN}گزارش کامل (با دسترسی فقط برای شما، chmod 600) ذخیره شد در:${NC}"
log_plain "${CYAN}${REPORT_FILE}${NC}"
log_plain ""
info "برای راهنمای رفع مشکلات، فایل docs/remediation_guide.md را در همین ریپازیتوری مطالعه کنید."

exit 0
