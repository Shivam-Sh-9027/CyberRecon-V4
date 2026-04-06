#!/usr/bin/env bash
# =============================================================================
#  CyberRecon V4 — Advanced Reconnaissance Automation Framework
#  ⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️
# =============================================================================
# Author  : Security Researcher
# Version : 4.0.0
# Requires: Kali Linux / Parrot OS (or any Debian-based distro with tools)
# Usage   : sudo bash cyberrecon_v4.sh -d <domain> [OPTIONS]
# =============================================================================

# ─── STRICT MODE ─────────────────────────────────────────────────────────────
set -uo pipefail
IFS=$'\n\t'

# ─── COLORS & STYLES ─────────────────────────────────────────────────────────
RED='\033[0;31m';    LRED='\033[1;31m'
GREEN='\033[0;32m';  LGREEN='\033[1;32m'
YELLOW='\033[1;33m'; LYELLOW='\033[0;33m'
BLUE='\033[0;34m';   LBLUE='\033[1;34m'
CYAN='\033[0;36m';   LCYAN='\033[1;36m'
MAGENTA='\033[0;35m';LMAGENTA='\033[1;35m'
WHITE='\033[1;37m';  GRAY='\033[0;37m'
BOLD='\033[1m';      DIM='\033[2m'
UNDERLINE='\033[4m'; BLINK='\033[5m'
RESET='\033[0m'

# ─── GLOBAL CONFIG ────────────────────────────────────────────────────────────
VERSION="4.0.0"
TOOL_NAME="CyberRecon V4"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
START_TIME=$(date +%s)

# Defaults (overridable via flags)
TARGET=""
TARGET_TYPE=""       # domain | ip | url
OUTPUT_DIR=""
HIBP_KEY=""
SCOPE_FILE=""
WORDLIST="/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
NUCLEI_SEVERITY="critical,high,medium"
THREADS=50
DEPTH=3
PASSIVE_ONLY=false
ACTIVE_ONLY=false
SKIP_MIRROR=false
SKIP_NUCLEI=false
SKIP_NMAP=false
VERBOSE=false
NO_COLOR=false
EXPORT_JSON=true
EXPORT_HTML=true
EXPORT_TXT=true

# ─── SPINNER FRAMES ──────────────────────────────────────────────────────────
SPINNER_FRAMES=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
SPINNER_PID=0

# ─── PHASE TRACKING ──────────────────────────────────────────────────────────
declare -A PHASE_STATUS
TOTAL_PHASES=9
CURRENT_PHASE=0

# ─── RESULT AGGREGATORS ──────────────────────────────────────────────────────
declare -a SUBDOMAINS=()
declare -a LIVE_HOSTS=()
declare -a DNS_RECORDS=()
declare -a TECHNOLOGIES=()
declare -a WAFS=()
declare -a EMAILS=()
declare -a URLS=()
declare -a PARAMS=()
declare -a ENDPOINTS=()
declare -a OPEN_PORTS=()
declare -a VULNS=()
declare -a OSINT_DATA=()

# =============================================================================
#  BANNER
# =============================================================================
banner() {
  clear
  echo -e "${LRED}"
  cat << 'BANNER'
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗   ██╗██╗  ██╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██║   ██║██║  ██║
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██║   ██║███████║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ╚██╗ ██╔╝╚════██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ╚████╔╝      ██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝     ╚═══╝       ╚═╝
BANNER
  echo -e "${RESET}"
  echo -e "  ${GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "  ${WHITE}${BOLD}  Advanced Reconnaissance Automation Framework${RESET}  ${DIM}v${VERSION}${RESET}"
  echo -e "  ${YELLOW}  ⚠️  FOR AUTHORIZED SECURITY TESTING ONLY — UNAUTHORIZED USE IS ILLEGAL ⚠️${RESET}"
  echo -e "  ${GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
}

# =============================================================================
#  LOGGING HELPERS
# =============================================================================
log_info()    { echo -e "  ${CYAN}[${WHITE}INFO${CYAN}]${RESET}  $*"; }
log_ok()      { echo -e "  ${GREEN}[${WHITE} OK ${GREEN}]${RESET}  $*"; }
log_warn()    { echo -e "  ${YELLOW}[${WHITE}WARN${YELLOW}]${RESET}  $*"; }
log_error()   { echo -e "  ${LRED}[${WHITE}ERR ${LRED}]${RESET}  $*" >&2; }
log_phase()   { echo -e "\n  ${LMAGENTA}[${WHITE}PHASE${LMAGENTA}]${RESET}  ${BOLD}$*${RESET}"; }
log_find()    { echo -e "  ${LGREEN}[${WHITE}FIND${LGREEN}]${RESET}  $*"; }
log_high()    { echo -e "  ${LRED}[${WHITE}HIGH${LRED}]${RESET}  🔴 $*"; }
log_medium()  { echo -e "  ${YELLOW}[${WHITE} MED${YELLOW}]${RESET}  🟡 $*"; }
log_low()     { echo -e "  ${GREEN}[${WHITE} LOW${GREEN}]${RESET}  🟢 $*"; }
log_skip()    { echo -e "  ${GRAY}[SKIP]${RESET}  ${DIM}$*${RESET}"; }
log_cmd()     { [[ "$VERBOSE" == true ]] && echo -e "  ${DIM}[CMD] → $*${RESET}"; }

# ─── SECTION HEADERS ─────────────────────────────────────────────────────────
section() {
  local title="$1"
  local width=80
  local pad=$(( (width - ${#title} - 2) / 2 ))
  echo ""
  echo -e "  ${LBLUE}╔$(printf '═%.0s' $(seq 1 $((width-2))))╗${RESET}"
  printf "  ${LBLUE}║${WHITE}${BOLD}%*s%s%*s${LBLUE}║${RESET}\n" $pad "" "$title" $((width - pad - ${#title} - 2)) ""
  echo -e "  ${LBLUE}╚$(printf '═%.0s' $(seq 1 $((width-2))))╝${RESET}"
  echo ""
}

# ─── PROGRESS BAR ─────────────────────────────────────────────────────────────
progress_bar() {
  local current=$1 total=$2 label="${3:-Processing}"
  local width=40
  local pct=$(( current * 100 / total ))
  local filled=$(( current * width / total ))
  local empty=$(( width - filled ))
  local bar="${GREEN}$(printf '█%.0s' $(seq 1 $filled))${RESET}${DIM}$(printf '░%.0s' $(seq 1 $empty))${RESET}"
  printf "\r  ${CYAN}[%-20s]${RESET} ${bar} ${WHITE}%3d%%${RESET}" "$label" "$pct"
  [[ $current -eq $total ]] && echo ""
}

# ─── SPINNER ──────────────────────────────────────────────────────────────────
spinner_start() {
  local msg="${1:-Running...}"
  (
    local i=0
    while true; do
      printf "\r  ${CYAN}${SPINNER_FRAMES[$i]}${RESET}  ${DIM}%s${RESET}" "$msg"
      i=$(( (i + 1) % ${#SPINNER_FRAMES[@]} ))
      sleep 0.08
    done
  ) &
  SPINNER_PID=$!
  disown "$SPINNER_PID" 2>&1 || true
}

spinner_stop() {
  if [[ $SPINNER_PID -ne 0 ]]; then
    kill "$SPINNER_PID" 2>&1 || true
    wait "$SPINNER_PID" 2>&1 || true
    SPINNER_PID=0
    printf "\r%80s\r" ""   # clear spinner line
  fi
}

# ─── PHASE HEADER ─────────────────────────────────────────────────────────────
phase_start() {
  CURRENT_PHASE=$(( CURRENT_PHASE + 1 ))
  local name="$1"
  local icon="${2:-🔍}"
  echo ""
  echo -e "  ${MAGENTA}┌─────────────────────────────────────────────────────────────────────────┐${RESET}"
  echo -e "  ${MAGENTA}│${RESET}  ${icon}  ${WHITE}${BOLD}Phase ${CURRENT_PHASE}/${TOTAL_PHASES} — ${name}${RESET}$(printf '%*s' $((45 - ${#name})) '')  ${MAGENTA}│${RESET}"
  echo -e "  ${MAGENTA}└─────────────────────────────────────────────────────────────────────────┘${RESET}"
  PHASE_STATUS["$name"]="running"
}

phase_done() {
  local name="$1"
  PHASE_STATUS["$name"]="done"
  echo -e "  ${GREEN}✔  Phase complete: ${WHITE}${name}${RESET}"
}

# =============================================================================
#  TOOL CHECKER
# =============================================================================
check_tools() {
  section "DEPENDENCY CHECK"
  local REQUIRED=(host whatweb whois dnsrecon dnsenum dig fierce nmap httpx nuclei katana sublist3r theHarvester wafw00f waybackurls httrack)
  local OPTIONAL=(dnsdumpster)
  local missing=()

  for tool in "${REQUIRED[@]}"; do
    if command -v "$tool" &>/dev/null; then
      log_ok "${tool}"
    else
      log_warn "${LRED}MISSING${RESET}: ${tool}"
      missing+=("$tool")
    fi
  done

  for tool in "${OPTIONAL[@]}"; do
    if command -v "$tool" &>/dev/null; then
      log_ok "${tool} ${DIM}(optional)${RESET}"
    else
      log_skip "${tool} — optional, skipping"
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo ""
    log_warn "Missing tools detected. Run with ${YELLOW}--install${RESET} to auto-install."
    log_warn "Or manually: ${CYAN}apt install ${missing[*]} 2>&1${RESET}"
  fi
  echo ""
}

# =============================================================================
#  AUTO INSTALL
# =============================================================================
auto_install() {
  section "AUTO INSTALL — KALI/PARROT"
  log_info "Updating package lists..."
  apt-get update -qq

  # Go-based tools
  local GO_TOOLS=(
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/tomnomnom/waybackurls@latest"
  )

  # Pip tools
  local PIP_TOOLS=("theHarvester" "dnsenum" "sublist3r")

  # APT tools
  local APT_TOOLS=("nmap" "whois" "dnsrecon" "fierce" "wafw00f" "whatweb" "httrack" "dnsutils")

  log_info "Installing APT packages..."
  apt-get install -y "${APT_TOOLS[@]}" -qq

  log_info "Installing Python tools..."
  pip3 install -q "${PIP_TOOLS[@]}" 2>&1 || true

  if command -v go &>/dev/null; then
    log_info "Installing Go-based tools..."
    for pkg in "${GO_TOOLS[@]}"; do
      go install "$pkg" &>/dev/null && log_ok "$pkg" || log_warn "Failed: $pkg"
    done
    export PATH="$PATH:$(go env GOPATH)/bin"
  else
    log_warn "Go not found — skipping httpx, nuclei, katana, waybackurls"
    log_info "Install Go: https://go.dev/doc/install"
  fi

  log_info "Updating nuclei templates..."
  nuclei -update-templates -silent 2>&1 || true

  log_ok "Installation complete!"
}

# =============================================================================
#  USAGE / HELP
# =============================================================================
usage() {
  banner
  echo -e "  ${WHITE}${BOLD}USAGE${RESET}"
  echo -e "    ${CYAN}sudo bash cyberrecon_v4.sh${RESET} ${YELLOW}-d <domain>${RESET} [OPTIONS]"
  echo ""
  echo -e "  ${WHITE}${BOLD}TARGET OPTIONS${RESET}"
  echo -e "    ${YELLOW}-d,  --domain${RESET}     <domain>      Target domain (e.g. example.com)"
  echo -e "    ${YELLOW}-i,  --ip${RESET}          <ip>          Target IP address"
  echo -e "    ${YELLOW}-u,  --url${RESET}          <url>         Full URL target"
  echo ""
  echo -e "  ${WHITE}${BOLD}RECON OPTIONS${RESET}"
  echo -e "    ${YELLOW}-o,  --output${RESET}      <dir>         Output directory (default: ./recon_<target>_<ts>)"
  echo -e "    ${YELLOW}-w,  --wordlist${RESET}    <file>        Custom DNS wordlist"
  echo -e "    ${YELLOW}-s,  --scope${RESET}        <file>        In-scope targets file (one per line)"
  echo -e "    ${YELLOW}-k,  --hibp-key${RESET}    <key>         HaveIBeenPwned API key"
  echo -e "    ${YELLOW}-t,  --threads${RESET}      <n>           Thread count (default: 50)"
  echo -e "    ${YELLOW}     --depth${RESET}         <n>           Katana crawl depth (default: 3)"
  echo -e "    ${YELLOW}     --severity${RESET}      <csv>         Nuclei severity filter (default: critical,high,medium)"
  echo ""
  echo -e "  ${WHITE}${BOLD}MODE FLAGS${RESET}"
  echo -e "    ${YELLOW}-p,  --passive-only${RESET}               Run passive recon only"
  echo -e "    ${YELLOW}-a,  --active-only${RESET}                Run active recon only"
  echo -e "    ${YELLOW}     --skip-mirror${RESET}                 Skip httrack website mirroring"
  echo -e "    ${YELLOW}     --skip-nuclei${RESET}                 Skip nuclei vulnerability scan"
  echo -e "    ${YELLOW}     --skip-nmap${RESET}                   Skip nmap port scan"
  echo ""
  echo -e "  ${WHITE}${BOLD}OUTPUT FLAGS${RESET}"
  echo -e "    ${YELLOW}     --no-json${RESET}                     Disable JSON export"
  echo -e "    ${YELLOW}     --no-html${RESET}                     Disable HTML report"
  echo -e "    ${YELLOW}     --no-txt${RESET}                      Disable TXT export"
  echo -e "    ${YELLOW}-v,  --verbose${RESET}                     Show all executed commands"
  echo ""
  echo -e "  ${WHITE}${BOLD}MISC${RESET}"
  echo -e "    ${YELLOW}     --install${RESET}                     Auto-install all dependencies"
  echo -e "    ${YELLOW}     --check${RESET}                       Check tool availability only"
  echo -e "    ${YELLOW}-h,  --help${RESET}                        Show this help"
  echo ""
  echo -e "  ${WHITE}${BOLD}EXAMPLES${RESET}"
  echo -e "    ${DIM}# Full recon on a domain${RESET}"
  echo -e "    ${CYAN}sudo bash cyberrecon_v4.sh -d example.com${RESET}"
  echo ""
  echo -e "    ${DIM}# Passive only with HIBP key${RESET}"
  echo -e "    ${CYAN}sudo bash cyberrecon_v4.sh -d example.com -p -k YOUR_HIBP_KEY${RESET}"
  echo ""
  echo -e "    ${DIM}# IP target, skip nuclei and mirror${RESET}"
  echo -e "    ${CYAN}sudo bash cyberrecon_v4.sh -i 192.168.1.1 --skip-nuclei --skip-mirror${RESET}"
  echo ""
}

# =============================================================================
#  ARG PARSER
# =============================================================================
parse_args() {
  [[ $# -eq 0 ]] && usage && exit 0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain)     TARGET="$2"; TARGET_TYPE="domain"; shift 2 ;;
      -i|--ip)         TARGET="$2"; TARGET_TYPE="ip";     shift 2 ;;
      -u|--url)        TARGET="$2"; TARGET_TYPE="url";    shift 2 ;;
      -o|--output)     OUTPUT_DIR="$2";                    shift 2 ;;
      -w|--wordlist)   WORDLIST="$2";                      shift 2 ;;
      -s|--scope)      SCOPE_FILE="$2";                    shift 2 ;;
      -k|--hibp-key)   HIBP_KEY="$2";                      shift 2 ;;
      -t|--threads)    THREADS="$2";                       shift 2 ;;
      --depth)         DEPTH="$2";                         shift 2 ;;
      --severity)      NUCLEI_SEVERITY="$2";               shift 2 ;;
      -p|--passive-only)  PASSIVE_ONLY=true;               shift   ;;
      -a|--active-only)   ACTIVE_ONLY=true;                shift   ;;
      --skip-mirror)   SKIP_MIRROR=true;                   shift   ;;
      --skip-nuclei)   SKIP_NUCLEI=true;                   shift   ;;
      --skip-nmap)     SKIP_NMAP=true;                     shift   ;;
      --no-json)       EXPORT_JSON=false;                  shift   ;;
      --no-html)       EXPORT_HTML=false;                  shift   ;;
      --no-txt)        EXPORT_TXT=false;                   shift   ;;
      -v|--verbose)    VERBOSE=true;                       shift   ;;
      --no-color)      NO_COLOR=true;                      shift   ;;
      --install)       auto_install; exit 0 ;;
      --check)         check_tools;  exit 0 ;;
      -h|--help)       usage;         exit 0 ;;
      *) log_error "Unknown argument: $1"; usage; exit 1 ;;
    esac
  done

  [[ -z "$TARGET" ]] && log_error "No target specified. Use -d, -i, or -u." && exit 1
}

# =============================================================================
#  TARGET NORMALIZATION
# =============================================================================
normalize_target() {
  section "TARGET VALIDATION & NORMALIZATION"

  # Strip protocol/path for domain
  TARGET=$(echo "$TARGET" | sed 's|^https\?://||;s|/.*$||;s|^www\.||')

  # Detect type if not set
  if [[ -z "$TARGET_TYPE" ]]; then
    if echo "$TARGET" | grep -qP '^\d{1,3}(\.\d{1,3}){3}$'; then
      TARGET_TYPE="ip"
    else
      TARGET_TYPE="domain"
    fi
  fi

  # Set output directory
  [[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="./recon_${TARGET}_${TIMESTAMP}"
  mkdir -p "$OUTPUT_DIR"/{passive,active,dns,web,network,osint,endpoints,raw,reports}

  log_ok "Target   : ${WHITE}${BOLD}${TARGET}${RESET}"
  log_ok "Type     : ${CYAN}${TARGET_TYPE}${RESET}"
  log_ok "Output   : ${CYAN}${OUTPUT_DIR}${RESET}"
  log_ok "Threads  : ${CYAN}${THREADS}${RESET}"
  log_ok "Timestamp: ${DIM}${TIMESTAMP}${RESET}"

  # Scope check
  if [[ -f "$SCOPE_FILE" ]]; then
    log_info "Scope file loaded: ${CYAN}${SCOPE_FILE}${RESET}"
  fi

  # Authorization reminder
  echo ""
  echo -e "  ${RED}╔═══════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "  ${RED}║  ⚠  YOU MUST HAVE WRITTEN AUTHORIZATION TO TEST THIS TARGET  ║${RESET}"
  echo -e "  ${RED}╚═══════════════════════════════════════════════════════════════╝${RESET}"
  echo ""
  read -rp "  Confirm you have authorization to test ${WHITE}${TARGET}${RESET} [yes/NO]: " CONFIRM
  [[ "$CONFIRM" != "yes" && "$CONFIRM" != "YES" ]] && log_error "Aborted — authorization not confirmed." && exit 1
}

# =============================================================================
#  HELPER: run with timeout + error handling
# =============================================================================
run_tool() {
  local tool="$1"; shift
  local outfile="$1"; shift
  local cmd="$*"

  log_cmd "$cmd"

  if ! command -v "$tool" &>/dev/null; then
    log_skip "$tool not found — skipping"
    return 0
  fi

  spinner_start "Running $tool..."

  # 🔥 MAIN FIX HERE
  timeout 300 bash -c "$cmd" | tee "$outfile" 2>&1 || {
    spinner_stop
    log_warn "$tool failed or timed out"
    return 0
  }

  spinner_stop

  local lines
  lines=$(wc -l < "$outfile" 2>&1 || echo 0)

  log_ok "$tool → ${GREEN}${lines}${RESET} lines saved → ${DIM}${outfile}${RESET}"
}

# =============================================================================
#  PHASE 1 — SUBDOMAIN ENUMERATION (PASSIVE)
# =============================================================================
phase_subdomain_enum() {
  phase_start "Subdomain Enumeration" "🌐"

  local out="${OUTPUT_DIR}/passive"

  # ── Sublist3r ─────────────────────────────────────────────────────────────
  log_info "Running Sublist3r..."
  if command -v sublist3r &>/dev/null; then
    spinner_start "Sublist3r — all sources..."
    timeout 300 sublist3r -d "$TARGET" -t "$THREADS" -o "${out}/sublist3r.txt" -v 2>&1 || true
    spinner_stop
    log_ok "Sublist3r done → ${out}/sublist3r.txt"
  else
    log_skip "sublist3r not found"
  fi

  # ── crt.sh (passive certificate transparency) ─────────────────────────────
  log_info "Querying crt.sh (certificate transparency)..."
  spinner_start "crt.sh CT logs..."
  curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" 2>&1 \
    | grep -oP '"name_value":"\K[^"]+' \
    | sed 's/\*\.//g' \
    | sort -u > "${out}/crtsh.txt" || true
  spinner_stop
  log_ok "crt.sh → $(wc -l < "${out}/crtsh.txt") results"

  # ── Chaos / AlienVault OTX (passive DNS) ──────────────────────────────────
  log_info "Querying AlienVault OTX..."
  spinner_start "AlienVault OTX passive DNS..."
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/passive_dns" 2>&1 \
    | grep -oP '"hostname":\s*"\K[^"]+' \
    | sort -u > "${out}/otx_dns.txt" || true
  spinner_stop
  log_ok "AlienVault OTX → $(wc -l < "${out}/otx_dns.txt") results"

  # ── Merge all subdomain sources ────────────────────────────────────────────
  log_info "Merging and deduplicating subdomains..."
  cat "${out}"/sublist3r.txt "${out}"/crtsh.txt "${out}"/otx_dns.txt 2>&1 \
    | grep -i "${TARGET}$" \
    | sort -u > "${out}/subdomains_all.txt"

  local count
  count=$(wc -l < "${out}/subdomains_all.txt")
  log_find "${LGREEN}${count}${RESET} unique subdomains found"
  mapfile -t SUBDOMAINS < "${out}/subdomains_all.txt"

  phase_done "Subdomain Enumeration"
}

# =============================================================================
#  PHASE 2 — OSINT (theHarvester, WHOIS, HIBP, Google Dorks)
# =============================================================================
phase_osint() {
  phase_start "OSINT Collection" "🕵️"

  local out="${OUTPUT_DIR}/osint"

  # ── theHarvester ──────────────────────────────────────────────────────────
  log_info "Running theHarvester (all sources)..."
  if command -v theHarvester &>/dev/null; then
    spinner_start "theHarvester gathering intel..."
    timeout 300 theHarvester -d "$TARGET" -l 500 -b all \
      -f "${out}/theharvester" 2>&1 || true
    spinner_stop
    log_ok "theHarvester complete → ${out}/theharvester.*"

    # Extract emails
    if [[ -f "${out}/theharvester.xml" ]]; then
      grep -oP '[\w.+-]+@[\w-]+\.[\w.-]+' "${out}/theharvester.xml" \
        | sort -u >> "${out}/emails.txt" || true
    fi
  else
    log_skip "theHarvester not found"
  fi

  # ── WHOIS ─────────────────────────────────────────────────────────────────
  log_info "Running WHOIS lookup..."
  if command -v whois &>/dev/null; then
    spinner_start "WHOIS query..."
    timeout 30 whois "$TARGET" > "${out}/whois.txt" 2>&1 || true
    spinner_stop
    # Extract emails from WHOIS
    grep -oP '[\w.+-]+@[\w-]+\.[\w.-]+' "${out}/whois.txt" \
      | sort -u >> "${out}/emails.txt" 2>&1 || true
    log_ok "WHOIS → ${out}/whois.txt"
  fi

  # ── HaveIBeenPwned ────────────────────────────────────────────────────────
  if [[ -n "$HIBP_KEY" ]]; then
    log_info "Checking HaveIBeenPwned for breach data..."
    while IFS= read -r email; do
      email_enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${email}'))" 2>&1 || echo "$email")
      local breach_resp
      breach_resp=$(curl -s -H "hibp-api-key: ${HIBP_KEY}" \
        "https://haveibeenpwned.com/api/v3/breachedaccount/${email_enc}" 2>&1 || echo "")
      if [[ -n "$breach_resp" && "$breach_resp" != "null" ]]; then
        echo "${email}: ${breach_resp}" >> "${out}/hibp_breaches.txt"
        log_high "BREACH: ${email} found in HIBP"
      fi
      sleep 1.5  # HIBP rate limit
    done < "${out}/emails.txt" 2>&1 || true
  else
    log_skip "HIBP key not provided — skipping breach check"
  fi

  # ── Deduplicate emails ────────────────────────────────────────────────────
  [[ -f "${out}/emails.txt" ]] && sort -u -o "${out}/emails.txt" "${out}/emails.txt"
  local email_count=0
  [[ -f "${out}/emails.txt" ]] && email_count=$(wc -l < "${out}/emails.txt")
  log_find "${LGREEN}${email_count}${RESET} unique email addresses"
  [[ -f "${out}/emails.txt" ]] && mapfile -t EMAILS < "${out}/emails.txt"

  # ── Google Dorks ──────────────────────────────────────────────────────────
  log_info "Generating Google Dorks..."
  cat > "${out}/google_dorks.txt" << DORKS
# ════════════════════════════════════════════════════════
#  CyberRecon V4 — Google Dorks for: ${TARGET}
# ════════════════════════════════════════════════════════

# ── Sensitive Files
site:${TARGET} ext:env
site:${TARGET} ext:sql
site:${TARGET} ext:bak
site:${TARGET} ext:cfg
site:${TARGET} ext:log
site:${TARGET} ext:xml
site:${TARGET} ext:yml
site:${TARGET} ext:yaml
site:${TARGET} ext:conf
site:${TARGET} ext:ini

# ── Exposed Admin/Login
site:${TARGET} inurl:admin
site:${TARGET} inurl:login
site:${TARGET} inurl:dashboard
site:${TARGET} inurl:portal
site:${TARGET} inurl:wp-admin
site:${TARGET} inurl:phpMyAdmin
site:${TARGET} inurl:webmail
site:${TARGET} inurl:cpanel

# ── Exposed Git/Dev
site:${TARGET} inurl:.git
site:${TARGET} inurl:.svn
site:${TARGET} "index of" inurl:.git
site:${TARGET} intext:"Index of /"

# ── API Endpoints
site:${TARGET} inurl:api
site:${TARGET} inurl:/api/v1
site:${TARGET} inurl:/api/v2
site:${TARGET} inurl:swagger
site:${TARGET} inurl:graphql
site:${TARGET} inurl:rest

# ── Credentials / Sensitive Content
site:${TARGET} intext:"password"
site:${TARGET} intext:"api_key"
site:${TARGET} intext:"secret"
site:${TARGET} intext:"token"
site:${TARGET} intext:"BEGIN RSA PRIVATE KEY"
site:${TARGET} intext:"AWS_SECRET_ACCESS_KEY"
site:${TARGET} intext:"db_password"
site:${TARGET} filetype:pdf confidential

# ── Subdomains
site:*.${TARGET}

# ── Cloud Buckets
site:s3.amazonaws.com "${TARGET}"
site:blob.core.windows.net "${TARGET}"
site:storage.googleapis.com "${TARGET}"

# ── Error Pages
site:${TARGET} "error" | "exception" | "stack trace"
DORKS
  log_ok "Google Dorks generated → ${out}/google_dorks.txt"
  log_info "Open dorks in browser: ${CYAN}xdg-open '${out}/google_dorks.txt'${RESET}"

  phase_done "OSINT Collection"
}

# =============================================================================
#  PHASE 3 — DNS & INFRASTRUCTURE MAPPING
# =============================================================================
phase_dns() {
  phase_start "DNS & Infrastructure Mapping" "🗺️"

  local out="${OUTPUT_DIR}/dns"

  # ── dig ───────────────────────────────────────────────────────────────────
  log_info "Running dig (ALL/A/MX/NS/TXT/SOA)..."
  if command -v dig &>/dev/null; then
    spinner_start "dig queries..."
    {
      echo "=== ANY ==="
      dig ANY "$TARGET" +noall +answer 2>&1 || true
      echo -e "\n=== A ==="
      dig A "$TARGET" +short 2>&1 || true
      echo -e "\n=== MX ==="
      dig MX "$TARGET" +short 2>&1 || true
      echo -e "\n=== NS ==="
      dig NS "$TARGET" +short 2>&1 || true
      echo -e "\n=== TXT ==="
      dig TXT "$TARGET" +short 2>&1 || true
      echo -e "\n=== SOA ==="
      dig SOA "$TARGET" +short 2>&1 || true
      echo -e "\n=== AAAA (IPv6) ==="
      dig AAAA "$TARGET" +short 2>&1 || true
      echo -e "\n=== AXFR (Zone Transfer Attempt) ==="
      dig AXFR "$TARGET" @"$(dig NS "$TARGET" +short | head -1)" 2>&1 || echo "AXFR not allowed (expected)"
    } > "${out}/dig_full.txt"
    spinner_stop
    log_ok "dig → ${out}/dig_full.txt"
  fi

  # ── host ──────────────────────────────────────────────────────────────────
  log_info "Running host lookup..."
  if command -v host &>/dev/null; then
    spinner_start "host resolution..."
    {
      echo "=== FORWARD LOOKUP ==="
      host "$TARGET" 2>&1 || true
      echo -e "\n=== IP LOOKUP ==="
      local resolved_ip
      resolved_ip=$(dig A "$TARGET" +short 2>&1 | head -1)
      [[ -n "$resolved_ip" ]] && host "$resolved_ip" 2>&1 || true
    } > "${out}/host.txt"
    spinner_stop
    log_ok "host → ${out}/host.txt"
  fi

  # ── dnsrecon ──────────────────────────────────────────────────────────────
  log_info "Running dnsrecon (std + brute + axfr)..."
  if command -v dnsrecon &>/dev/null; then
    spinner_start "dnsrecon std..."
    timeout 120 dnsrecon -d "$TARGET" -t std -j "${out}/dnsrecon_std.json" \
      2>&1 > "${out}/dnsrecon_std.txt" || true
    spinner_stop

    if [[ -f "$WORDLIST" ]]; then
      spinner_start "dnsrecon brute..."
      timeout 300 dnsrecon -d "$TARGET" -t brt -D "$WORDLIST" \
        -j "${out}/dnsrecon_brute.json" 2>&1 > "${out}/dnsrecon_brute.txt" || true
      spinner_stop
      log_ok "dnsrecon brute → ${out}/dnsrecon_brute.txt"
    else
      log_skip "Wordlist not found: $WORDLIST — skipping brute"
    fi

    spinner_start "dnsrecon axfr..."
    timeout 60 dnsrecon -d "$TARGET" -t axfr 2>&1 > "${out}/dnsrecon_axfr.txt" || true
    spinner_stop

    # Check AXFR success
    if grep -qi "zone transfer" "${out}/dnsrecon_axfr.txt" 2>&1; then
      log_high "ZONE TRANSFER POSSIBLE on ${TARGET}!"
    else
      log_ok "AXFR check complete (zone transfer not allowed)"
    fi
    log_ok "dnsrecon → ${out}/dnsrecon_*.txt"
  else
    log_skip "dnsrecon not found"
  fi

  # ── dnsenum ───────────────────────────────────────────────────────────────
  log_info "Running dnsenum..."
  if command -v dnsenum &>/dev/null; then
    spinner_start "dnsenum enumeration..."
    timeout 300 dnsenum --threads "$THREADS" --enum "$TARGET" \
      -o "${out}/dnsenum.xml" 2>&1 > "${out}/dnsenum.txt" || true
    spinner_stop
    log_ok "dnsenum → ${out}/dnsenum.txt"
  else
    log_skip "dnsenum not found"
  fi

  # ── fierce ────────────────────────────────────────────────────────────────
  log_info "Running fierce (DNS bruteforce)..."
  if command -v fierce &>/dev/null; then
    spinner_start "fierce DNS brute..."
    timeout 300 fierce --domain "$TARGET" \
      2>&1 > "${out}/fierce.txt" || true
    spinner_stop
    log_ok "fierce → ${out}/fierce.txt"
  else
    log_skip "fierce not found"
  fi

  # ── Parse DNS records ─────────────────────────────────────────────────────
  log_info "Parsing DNS records..."
  {
    grep -oP 'IN\s+\K\w+' "${out}/dig_full.txt" 2>&1
    grep -P 'A|MX|NS|TXT|CNAME|SOA' "${out}/dnsrecon_std.txt" 2>&1
  } | sort -u >> "${out}/dns_records_summary.txt" || true

  mapfile -t DNS_RECORDS < <(cat "${out}/dig_full.txt" "${out}/dnsrecon_std.txt" 2>&1 | sort -u)

  echo ""
  echo -e "  ${LBLUE}DNS Quick Summary:${RESET}"
  dig A "$TARGET" +short 2>&1 | while read -r ip; do
    log_find "  A record  → ${WHITE}${ip}${RESET}"
  done
  dig MX "$TARGET" +short 2>&1 | while read -r mx; do
    log_find "  MX record → ${WHITE}${mx}${RESET}"
  done
  dig NS "$TARGET" +short 2>&1 | while read -r ns; do
    log_find "  NS record → ${WHITE}${ns}${RESET}"
  done

  phase_done "DNS & Infrastructure Mapping"
}

# =============================================================================
#  PHASE 4 — WEB TECHNOLOGY & WAF DETECTION
# =============================================================================
phase_web_tech() {
  phase_start "Web Technology & WAF Detection" "🛡️"

  local out="${OUTPUT_DIR}/web"

  # ── whatweb ───────────────────────────────────────────────────────────────
  log_info "Running whatweb (aggressive mode)..."
  if command -v whatweb &>/dev/null; then
    spinner_start "whatweb scanning..."
    timeout 120 whatweb -a 3 --log-json="${out}/whatweb.json" \
      "https://${TARGET}" 2>&1 > "${out}/whatweb.txt" || \
    timeout 120 whatweb -a 3 --log-json="${out}/whatweb.json" \
      "http://${TARGET}" 2>&1 > "${out}/whatweb.txt" || true
    spinner_stop

    # Parse technologies
    if [[ -f "${out}/whatweb.json" ]]; then
      grep -oP '"[A-Z][^"]+":' "${out}/whatweb.json" \
        | tr -d '":' | sort -u > "${out}/technologies.txt" || true
      log_ok "whatweb → $(wc -l < "${out}/technologies.txt") technologies detected"
      mapfile -t TECHNOLOGIES < "${out}/technologies.txt"
      for tech in "${TECHNOLOGIES[@]:0:10}"; do
        log_find "  Tech: ${CYAN}${tech}${RESET}"
      done
    fi
  else
    log_skip "whatweb not found"
  fi

  # ── wafw00f ───────────────────────────────────────────────────────────────
  log_info "Running wafw00f (WAF detection)..."
  if command -v wafw00f &>/dev/null; then
    spinner_start "wafw00f detecting WAFs..."
    timeout 60 wafw00f -a "https://${TARGET}" \
      2>&1 > "${out}/wafw00f.txt" || \
    timeout 60 wafw00f -a "http://${TARGET}" \
      2>&1 > "${out}/wafw00f.txt" || true
    spinner_stop

    if grep -qi "is behind" "${out}/wafw00f.txt" 2>&1; then
      local waf_name
      waf_name=$(grep -i "is behind" "${out}/wafw00f.txt" | head -1)
      log_medium "WAF Detected: ${YELLOW}${waf_name}${RESET}"
      WAFS+=("$waf_name")
    elif grep -qi "no WAF" "${out}/wafw00f.txt" 2>&1; then
      log_ok "No WAF detected — ${GREEN}direct access likely${RESET}"
    fi
    log_ok "wafw00f → ${out}/wafw00f.txt"
  else
    log_skip "wafw00f not found"
  fi

  phase_done "Web Technology & WAF Detection"
}

# =============================================================================
#  PHASE 5 — ACTIVE RECON (httpx, katana, httrack)
# =============================================================================
phase_active_recon() {
  [[ "$PASSIVE_ONLY" == true ]] && log_skip "Passive-only mode — skipping active recon" && return

  phase_start "Active Recon — Live Detection & Crawling" "⚡"

  local out="${OUTPUT_DIR}/active"

  # ── Build target list ─────────────────────────────────────────────────────
  log_info "Building target list for active probing..."
  local targets_file="${out}/targets_input.txt"

  {
    echo "$TARGET"
    cat "${OUTPUT_DIR}/passive/subdomains_all.txt" 2>&1
  } | sort -u > "$targets_file"

  local total_targets
  total_targets=$(wc -l < "$targets_file")
  log_info "Total targets to probe: ${WHITE}${total_targets}${RESET}"

  # ── httpx ─────────────────────────────────────────────────────────────────
  log_info "Running httpx (live host detection)..."
  if command -v httpx &>/dev/null; then
    spinner_start "httpx probing ${total_targets} targets..."
    timeout 300 httpx -l "$targets_file" \
      -threads "$THREADS" \
      -status-code \
      -title \
      -tech-detect \
      -follow-redirects \
      -json \
      -o "${out}/httpx.json" \
      2>&1 > "${out}/httpx_raw.txt" || true
    spinner_stop

    # Extract live URLs
    if [[ -f "${out}/httpx.json" ]]; then
      grep -oP '"url":\s*"\K[^"]+' "${out}/httpx.json" \
        | sort -u > "${out}/live_hosts.txt" 2>&1 || true
      local live_count
      live_count=$(wc -l < "${out}/live_hosts.txt")
      log_find "${LGREEN}${live_count}${RESET} live hosts detected"
      mapfile -t LIVE_HOSTS < "${out}/live_hosts.txt"

      # Show status codes
      echo ""
      echo -e "  ${LBLUE}Live Hosts Summary:${RESET}"
      head -20 "${out}/httpx_raw.txt" 2>&1 | while IFS= read -r line; do
        if echo "$line" | grep -q "200"; then
          echo -e "    ${GREEN}${line}${RESET}"
        elif echo "$line" | grep -q "301\|302"; then
          echo -e "    ${YELLOW}${line}${RESET}"
        elif echo "$line" | grep -q "403\|404"; then
          echo -e "    ${GRAY}${line}${RESET}"
        elif echo "$line" | grep -q "500"; then
          echo -e "    ${RED}${line}${RESET}"
        else
          echo -e "    ${line}"
        fi
      done
    fi
  else
    log_skip "httpx not found — using fallback curl check"
    # Fallback: basic curl check
    while IFS= read -r host; do
      local code
      code=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 5 "https://${host}" 2>&1 || echo "000")
      [[ "$code" != "000" && "$code" != "400" ]] && \
        echo "https://${host}" >> "${out}/live_hosts.txt" && \
        LIVE_HOSTS+=("https://${host}")
    done < "$targets_file"
  fi

  # ── waybackurls ───────────────────────────────────────────────────────────
  log_info "Running waybackurls (historical URLs)..."
  if command -v waybackurls &>/dev/null; then
    spinner_start "fetching wayback URLs..."
    echo "$TARGET" | timeout 180 waybackurls 2>&1 \
      | sort -u > "${out}/wayback_urls.txt" || true
    spinner_stop
    local wb_count
    wb_count=$(wc -l < "${out}/wayback_urls.txt")
    log_find "${LGREEN}${wb_count}${RESET} historical URLs from Wayback Machine"
  else
    # Fallback via Wayback CDX API
    log_info "Fetching Wayback URLs via CDX API..."
    spinner_start "CDX API query..."
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey" \
      2>&1 | sort -u > "${out}/wayback_urls.txt" || true
    spinner_stop
    log_ok "Wayback CDX → $(wc -l < "${out}/wayback_urls.txt") URLs"
  fi

  # ── katana ────────────────────────────────────────────────────────────────
  log_info "Running katana (deep crawler, depth ${DEPTH})..."
  if command -v katana &>/dev/null; then
    local live_input="${out}/live_hosts.txt"
    [[ ! -f "$live_input" ]] && echo "https://${TARGET}" > "$live_input"

    spinner_start "katana crawling (depth ${DEPTH})..."
    timeout 600 katana -list "$live_input" \
      -depth "$DEPTH" \
      -jc \
      -concurrency "$THREADS" \
      -output "${out}/katana.txt" \
      2>&1 || true
    spinner_stop
    log_ok "katana → $(wc -l < "${out}/katana.txt" 2>&1 || echo 0) URLs crawled"
  else
    log_skip "katana not found"
  fi

  # ── httrack (website mirror) ───────────────────────────────────────────────
  if [[ "$SKIP_MIRROR" == false ]]; then
    log_info "Running httrack (website mirror)..."
    if command -v httrack &>/dev/null; then
      spinner_start "httrack mirroring site..."
      timeout 600 httrack "https://${TARGET}" -O "${out}/httrack_mirror" \
        -r3 -%e0 --quiet 2>&1 || \
      timeout 600 httrack "http://${TARGET}" -O "${out}/httrack_mirror" \
        -r3 -%e0 --quiet 2>&1 || true
      spinner_stop
      log_ok "httrack mirror → ${out}/httrack_mirror/"
    else
      log_skip "httrack not found"
    fi
  else
    log_skip "httrack mirroring skipped (--skip-mirror)"
  fi

  phase_done "Active Recon — Live Detection & Crawling"
}

# =============================================================================
#  PHASE 6 — ATTACK SURFACE EXPANSION
# =============================================================================
phase_attack_surface() {
  phase_start "Attack Surface Expansion" "🔎"

  local out="${OUTPUT_DIR}/endpoints"
  local active="${OUTPUT_DIR}/active"

  # ── Merge all URLs ────────────────────────────────────────────────────────
  log_info "Merging all URL sources..."
  {
    cat "${active}/wayback_urls.txt"  2>&1
    cat "${active}/katana.txt"         2>&1
  } | sort -u > "${out}/all_urls.txt"

  local total_urls
  total_urls=$(wc -l < "${out}/all_urls.txt")
  log_find "${LGREEN}${total_urls}${RESET} total unique URLs merged"

  mapfile -t URLS < "${out}/all_urls.txt"

  # ── Parameter extraction ──────────────────────────────────────────────────
  log_info "Extracting URL parameters..."
  grep -oP '[?&][^=&\s#]+=[^&\s#]*' "${out}/all_urls.txt" 2>&1 \
    | sed 's/^[?&]//' \
    | cut -d= -f1 \
    | sort -u > "${out}/parameters.txt" || true

  local param_count
  param_count=$(wc -l < "${out}/parameters.txt")
  log_find "${LGREEN}${param_count}${RESET} unique parameters extracted"
  mapfile -t PARAMS < "${out}/parameters.txt"

  # ── Sensitive endpoint detection ──────────────────────────────────────────
  log_info "Identifying sensitive/interesting endpoints..."
  local patterns=(
    '\.env'
    '\.git'
    '\.svn'
    '\.DS_Store'
    'backup'
    'admin'
    'login'
    'dashboard'
    'portal'
    'api/'
    '/v[0-9]/'
    'swagger'
    'graphql'
    'config'
    'setup'
    'install'
    'phpinfo'
    'phpmyadmin'
    'wp-admin'
    'wp-login'
    'wp-config'
    'uploads'
    'debug'
    'console'
    'actuator'
    'metrics'
    'health'
    '_debug_toolbar'
    'secret'
    'passwd'
    'shadow'
    'id_rsa'
    '\.sql'
    '\.bak'
    '\.log'
    '\.cfg'
    '\.conf'
    '\.xml'
    '\.json'
    's3\.amazonaws'
    'bucket'
    '\.pem'
    'token'
    'credentials'
  )

  local pattern_regex
  pattern_regex=$(IFS='|'; echo "${patterns[*]}")

  grep -Ei "$pattern_regex" "${out}/all_urls.txt" 2>&1 \
    | sort -u > "${out}/interesting_endpoints.txt" || true

  local ep_count
  ep_count=$(wc -l < "${out}/interesting_endpoints.txt")
  log_find "${LGREEN}${ep_count}${RESET} interesting endpoints identified"

  # ── Tag and color endpoints ────────────────────────────────────────────────
  echo ""
  echo -e "  ${LBLUE}High-Value Endpoints:${RESET}"
  local high_patterns='\.env|\.git|backup|admin|passwd|id_rsa|\.sql|credentials|token|secret|s3\.'
  local med_patterns='login|dashboard|api/|swagger|graphql|config|wp-admin|phpmyadmin|actuator'

  while IFS= read -r ep; do
    if echo "$ep" | grep -qEi "$high_patterns"; then
      log_high "[HIGH] ${ep}"
      echo "HIGH: ${ep}" >> "${out}/endpoints_tagged.txt"
    elif echo "$ep" | grep -qEi "$med_patterns"; then
      log_medium "[MED]  ${ep}"
      echo "MED: ${ep}" >> "${out}/endpoints_tagged.txt"
    else
      log_low "[LOW]  ${ep}"
      echo "LOW: ${ep}" >> "${out}/endpoints_tagged.txt"
    fi
  done < <(head -50 "${out}/interesting_endpoints.txt" 2>&1) || true

  mapfile -t ENDPOINTS < "${out}/interesting_endpoints.txt"

  phase_done "Attack Surface Expansion"
}

# =============================================================================
#  PHASE 7 — NETWORK SCANNING (nmap)
# =============================================================================
phase_network_scan() {
  [[ "$PASSIVE_ONLY" == true ]] && log_skip "Passive-only — skipping nmap" && return
  [[ "$SKIP_NMAP" == true ]]    && log_skip "--skip-nmap flag set"          && return

  phase_start "Network & Port Scanning" "🔌"

  local out="${OUTPUT_DIR}/network"
  local target_ip
  target_ip=$(dig A "$TARGET" +short 2>&1 | head -1 || echo "$TARGET")

  # ── nmap ──────────────────────────────────────────────────────────────────
  log_info "Running nmap (-sC -sV) on ${WHITE}${target_ip}${RESET}..."
  if command -v nmap &>/dev/null; then
    spinner_start "nmap service scan (this may take a while)..."
    timeout 600 nmap -sC -sV -T4 \
      --open \
      -oN "${out}/nmap_scan.txt" \
      -oX "${out}/nmap_scan.xml" \
      "$target_ip" \
      2>&1 || true
    spinner_stop
    log_ok "nmap → ${out}/nmap_scan.txt"

    # Parse open ports
    log_info "Parsing open ports..."
    grep -P '^\d+/tcp\s+open' "${out}/nmap_scan.txt" 2>&1 \
      | sort -t/ -k1,1n > "${out}/open_ports.txt" || true

    local port_count
    port_count=$(wc -l < "${out}/open_ports.txt")
    log_find "${LGREEN}${port_count}${RESET} open ports detected"

    echo ""
    echo -e "  ${LBLUE}Open Ports:${RESET}"

    local uncommon_ports=('21' '22' '23' '25' '53' '110' '111' '135' '139' '143' '443' '445' '3306' '3389' '5432' '5900' '6379' '8080' '8443' '27017')

    while IFS= read -r line; do
      local port
      port=$(echo "$line" | cut -d/ -f1)
      OPEN_PORTS+=("$line")

      # Flag dangerous services
      if echo "$line" | grep -qiE 'ms-sql|rdp|telnet|ftp|smb|vnc|redis|mongo|mysql|postgres'; then
        log_high "DANGEROUS SERVICE: ${line}"
      elif echo "${uncommon_ports[@]}" | grep -qw "$port"; then
        log_medium "NOTABLE PORT: ${line}"
      else
        log_low "  ${line}"
      fi
    done < "${out}/open_ports.txt" 2>&1 || true

    mapfile -t OPEN_PORTS < "${out}/open_ports.txt"
  else
    log_skip "nmap not found"
  fi

  phase_done "Network & Port Scanning"
}

# =============================================================================
#  PHASE 8 — VULNERABILITY SCANNING (nuclei)
# =============================================================================
phase_vuln_scan() {
  [[ "$PASSIVE_ONLY" == true ]] && log_skip "Passive-only — skipping nuclei" && return
  [[ "$SKIP_NUCLEI" == true ]]  && log_skip "--skip-nuclei flag set"          && return

  phase_start "Vulnerability Scanning (nuclei)" "💀"

  local out="${OUTPUT_DIR}/network"
  local live_file="${OUTPUT_DIR}/active/live_hosts.txt"

  # Fallback to main target if no live hosts file
  if [[ ! -f "$live_file" ]]; then
    echo "https://${TARGET}" > "${out}/nuclei_targets.txt"
    live_file="${out}/nuclei_targets.txt"
  fi

  if command -v nuclei &>/dev/null; then
    log_info "Updating nuclei templates..."
    spinner_start "nuclei template update..."
    nuclei -update-templates -silent 2>&1 || true
    spinner_stop

    log_info "Running nuclei (severity: ${NUCLEI_SEVERITY})..."
    spinner_start "nuclei scanning live hosts..."
    timeout 900 nuclei \
      -l "$live_file" \
      -severity "$NUCLEI_SEVERITY" \
      -threads "$THREADS" \
      -json \
      -o "${out}/nuclei_results.json" \
      2>&1 > "${out}/nuclei_results.txt" || true
    spinner_stop

    log_ok "nuclei → ${out}/nuclei_results.txt"

    # Parse and display results
    if [[ -f "${out}/nuclei_results.txt" ]]; then
      local vuln_count
      vuln_count=$(wc -l < "${out}/nuclei_results.txt")
      log_find "${LGREEN}${vuln_count}${RESET} nuclei findings"

      echo ""
      echo -e "  ${LBLUE}Nuclei Findings:${RESET}"
      while IFS= read -r line; do
        if echo "$line" | grep -qi "critical"; then
          echo -e "  ${LRED}[CRITICAL]${RESET} ${line}"
        elif echo "$line" | grep -qi "\[high\]"; then
          echo -e "  ${RED}[HIGH]${RESET}     ${line}"
        elif echo "$line" | grep -qi "\[medium\]"; then
          echo -e "  ${YELLOW}[MEDIUM]${RESET}   ${line}"
        else
          echo -e "  ${GRAY}${line}${RESET}"
        fi
        VULNS+=("$line")
      done < "${out}/nuclei_results.txt" 2>&1 || true
    fi
  else
    log_skip "nuclei not found — skipping vulnerability scan"
  fi

  phase_done "Vulnerability Scanning"
}

# =============================================================================
#  PHASE 9 — REPORT GENERATION
# =============================================================================
phase_report() {
  phase_start "Report Generation" "📊"

  local report_dir="${OUTPUT_DIR}/reports"
  local end_time=$(date +%s)
  local duration=$(( end_time - START_TIME ))

  # ── TXT REPORT ─────────────────────────────────────────────────────────────
  if [[ "$EXPORT_TXT" == true ]]; then
    local txt_report="${report_dir}/cyberrecon_v4_${TARGET}_${TIMESTAMP}.txt"
    {
      echo "╔══════════════════════════════════════════════════════════════════════════════╗"
      echo "║              CyberRecon V4 — Recon Report                                  ║"
      echo "╠══════════════════════════════════════════════════════════════════════════════╣"
      echo "║  Target  : ${TARGET}"
      echo "║  Type    : ${TARGET_TYPE}"
      echo "║  Date    : $(date)"
      echo "║  Duration: ${duration}s"
      echo "╚══════════════════════════════════════════════════════════════════════════════╝"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 1. TARGET SUMMARY"
      echo "═══════════════════════════════════════════════"
      echo "Target      : ${TARGET}"
      echo "Type        : ${TARGET_TYPE}"
      echo "IP Address  : $(dig A "$TARGET" +short 2>&1 | head -1 || echo 'N/A')"
      echo "Subdomains  : ${#SUBDOMAINS[@]}"
      echo "Live Hosts  : ${#LIVE_HOSTS[@]}"
      echo "Emails      : ${#EMAILS[@]}"
      echo "Open Ports  : ${#OPEN_PORTS[@]}"
      echo "Vulns Found : ${#VULNS[@]}"
      echo "URLs Found  : ${#URLS[@]}"
      echo "Endpoints   : ${#ENDPOINTS[@]}"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 2. SUBDOMAINS (${#SUBDOMAINS[@]} unique)"
      echo "═══════════════════════════════════════════════"
      printf '%s\n' "${SUBDOMAINS[@]}" 2>&1 || echo "None found"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 3. LIVE HOSTS (${#LIVE_HOSTS[@]})"
      echo "═══════════════════════════════════════════════"
      printf '%s\n' "${LIVE_HOSTS[@]}" 2>&1 || echo "None detected"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 4. DNS RECORDS"
      echo "═══════════════════════════════════════════════"
      cat "${OUTPUT_DIR}/dns/dig_full.txt" 2>&1 || echo "No DNS data"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 5. TECHNOLOGIES DETECTED"
      echo "═══════════════════════════════════════════════"
      printf '%s\n' "${TECHNOLOGIES[@]}" 2>&1 || echo "None detected"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 6. WAF DETECTION"
      echo "═══════════════════════════════════════════════"
      cat "${OUTPUT_DIR}/web/wafw00f.txt" 2>&1 || echo "No WAF data"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 7. EMAILS & OSINT"
      echo "═══════════════════════════════════════════════"
      printf '%s\n' "${EMAILS[@]}" 2>&1 || echo "No emails found"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 8. HISTORICAL URLS (top 100)"
      echo "═══════════════════════════════════════════════"
      head -100 "${OUTPUT_DIR}/active/wayback_urls.txt" 2>&1 || echo "No historical URLs"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 9. PARAMETERS (${#PARAMS[@]} unique)"
      echo "═══════════════════════════════════════════════"
      printf '%s\n' "${PARAMS[@]}" 2>&1 || echo "None found"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 10. INTERESTING ENDPOINTS"
      echo "═══════════════════════════════════════════════"
      cat "${OUTPUT_DIR}/endpoints/endpoints_tagged.txt" 2>&1 || echo "None found"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 11. OPEN PORTS & SERVICES"
      echo "═══════════════════════════════════════════════"
      cat "${OUTPUT_DIR}/network/open_ports.txt" 2>&1 || echo "No scan data"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 12. VULNERABILITIES (nuclei)"
      echo "═══════════════════════════════════════════════"
      cat "${OUTPUT_DIR}/network/nuclei_results.txt" 2>&1 || echo "No vulnerabilities found / scan skipped"
      echo ""

      echo "═══════════════════════════════════════════════"
      echo " 13. GOOGLE DORKS"
      echo "═══════════════════════════════════════════════"
      cat "${OUTPUT_DIR}/osint/google_dorks.txt" 2>&1
      echo ""

    } > "$txt_report"
    log_ok "TXT Report → ${CYAN}${txt_report}${RESET}"
  fi

  # ── JSON REPORT ────────────────────────────────────────────────────────────
  if [[ "$EXPORT_JSON" == true ]]; then
    local json_report="${report_dir}/cyberrecon_v4_${TARGET}_${TIMESTAMP}.json"
    python3 - << PYTHON > "$json_report" 2>&1 || true
import json, datetime

report = {
    "meta": {
        "tool": "CyberRecon V4",
        "version": "${VERSION}",
        "target": "${TARGET}",
        "target_type": "${TARGET_TYPE}",
        "timestamp": "$(date -Iseconds)",
        "duration_seconds": ${duration}
    },
    "subdomains": $(printf '%s\n' "${SUBDOMAINS[@]}" 2>&1 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().splitlines()))" 2>&1 || echo '[]'),
    "live_hosts": $(printf '%s\n' "${LIVE_HOSTS[@]}" 2>&1 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().splitlines()))" 2>&1 || echo '[]'),
    "emails": $(printf '%s\n' "${EMAILS[@]}" 2>&1 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().splitlines()))" 2>&1 || echo '[]'),
    "technologies": $(printf '%s\n' "${TECHNOLOGIES[@]}" 2>&1 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().splitlines()))" 2>&1 || echo '[]'),
    "open_ports": $(printf '%s\n' "${OPEN_PORTS[@]}" 2>&1 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().splitlines()))" 2>&1 || echo '[]'),
    "parameters": $(printf '%s\n' "${PARAMS[@]}" 2>&1 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().splitlines()))" 2>&1 || echo '[]'),
    "vulnerabilities": $(cat "${OUTPUT_DIR}/network/nuclei_results.txt" 2>&1 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().splitlines()))" 2>&1 || echo '[]'),
    "interesting_endpoints": $(cat "${OUTPUT_DIR}/endpoints/interesting_endpoints.txt" 2>&1 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().splitlines()))" 2>&1 || echo '[]')
}
print(json.dumps(report, indent=2))
PYTHON
    log_ok "JSON Report → ${CYAN}${json_report}${RESET}"
  fi

  # ── HTML REPORT ────────────────────────────────────────────────────────────
  if [[ "$EXPORT_HTML" == true ]]; then
    local html_report="${report_dir}/cyberrecon_v4_${TARGET}_${TIMESTAMP}.html"
    generate_html_report "$html_report"
    log_ok "HTML Report → ${CYAN}${html_report}${RESET}"
  fi

  phase_done "Report Generation"
}

# =============================================================================
#  HTML REPORT GENERATOR
# =============================================================================
generate_html_report() {
  local outfile="$1"
  local end_time=$(date +%s)
  local duration=$(( end_time - START_TIME ))
  local ip_addr
  ip_addr=$(dig A "$TARGET" +short 2>&1 | head -1 || echo "N/A")

  cat > "$outfile" << HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>CyberRecon V4 — ${TARGET}</title>
  <style>
    :root {
      --bg: #0a0e1a; --bg2: #111827; --bg3: #1a2234;
      --accent: #00d4ff; --accent2: #7c3aed;
      --red: #ef4444; --yellow: #f59e0b; --green: #10b981;
      --text: #e2e8f0; --muted: #64748b; --border: #1e293b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', monospace; background: var(--bg); color: var(--text); }
    header {
      background: linear-gradient(135deg, #0a0e1a 0%, #1a0a2e 50%, #0a1a1a 100%);
      border-bottom: 1px solid var(--accent);
      padding: 2rem; text-align: center;
    }
    header h1 { font-size: 2.5rem; color: var(--accent); letter-spacing: 4px; }
    header p  { color: var(--muted); margin-top: 0.5rem; font-size: 0.9rem; }
    .warning {
      background: #2d1b00; border: 1px solid var(--yellow);
      color: var(--yellow); padding: 0.75rem 1.5rem;
      text-align: center; font-size: 0.85rem;
    }
    .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-card {
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 8px; padding: 1.5rem; text-align: center;
    }
    .stat-card .num { font-size: 2rem; font-weight: bold; color: var(--accent); }
    .stat-card .lbl { color: var(--muted); font-size: 0.8rem; margin-top: 0.25rem; }
    section.panel {
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden;
    }
    .panel-header {
      background: var(--bg3); padding: 1rem 1.5rem;
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 0.75rem;
      cursor: pointer; user-select: none;
    }
    .panel-header h2 { font-size: 1rem; color: var(--accent); flex: 1; }
    .panel-header .badge {
      background: var(--accent2); color: white;
      padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.75rem;
    }
    .panel-body { padding: 1.5rem; display: block; }
    .panel-body.hidden { display: none; }
    pre, code {
      background: var(--bg); border: 1px solid var(--border);
      padding: 1rem; border-radius: 6px; overflow-x: auto;
      font-size: 0.82rem; line-height: 1.6; white-space: pre-wrap;
      word-break: break-all; max-height: 400px; overflow-y: auto;
    }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { background: var(--bg3); color: var(--accent); padding: 0.75rem 1rem; text-align: left; }
    td { padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }
    tr:hover td { background: var(--bg3); }
    .tag { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    .tag.high     { background: #450a0a; color: var(--red); }
    .tag.medium   { background: #2d1f00; color: var(--yellow); }
    .tag.low      { background: #052e1a; color: var(--green); }
    .tag.critical { background: #5c0a0a; color: #ff6b6b; border: 1px solid #ef4444; }
    footer { text-align: center; padding: 2rem; color: var(--muted); font-size: 0.8rem; }
  </style>
</head>
<body>
<header>
  <h1>⚡ CYBERRECON V4</h1>
  <p>Advanced Reconnaissance Report &nbsp;|&nbsp; Target: <strong>${TARGET}</strong> &nbsp;|&nbsp; $(date)</p>
</header>
<div class="warning">⚠️ THIS REPORT CONTAINS SENSITIVE SECURITY INFORMATION — FOR AUTHORIZED PERSONNEL ONLY ⚠️</div>

<div class="container">

  <!-- STATS -->
  <div class="stats-grid">
    <div class="stat-card"><div class="num">${#SUBDOMAINS[@]}</div><div class="lbl">Subdomains</div></div>
    <div class="stat-card"><div class="num">${#LIVE_HOSTS[@]}</div><div class="lbl">Live Hosts</div></div>
    <div class="stat-card"><div class="num">${#EMAILS[@]}</div><div class="lbl">Emails</div></div>
    <div class="stat-card"><div class="num">${#OPEN_PORTS[@]}</div><div class="lbl">Open Ports</div></div>
    <div class="stat-card"><div class="num">${#VULNS[@]}</div><div class="lbl">Findings</div></div>
    <div class="stat-card"><div class="num">${#PARAMS[@]}</div><div class="lbl">Parameters</div></div>
    <div class="stat-card"><div class="num">${#ENDPOINTS[@]}</div><div class="lbl">Endpoints</div></div>
    <div class="stat-card"><div class="num">${duration}s</div><div class="lbl">Scan Duration</div></div>
  </div>

  <!-- TARGET SUMMARY -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>🎯</span><h2>Target Summary</h2>
    </div>
    <div class="panel-body">
      <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Target</td><td><strong>${TARGET}</strong></td></tr>
        <tr><td>Type</td><td>${TARGET_TYPE}</td></tr>
        <tr><td>IP Address</td><td>${ip_addr}</td></tr>
        <tr><td>Scan Date</td><td>$(date)</td></tr>
        <tr><td>Output Dir</td><td>${OUTPUT_DIR}</td></tr>
      </table>
    </div>
  </section>

  <!-- SUBDOMAINS -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>🌐</span><h2>Subdomains</h2><span class="badge">${#SUBDOMAINS[@]}</span>
    </div>
    <div class="panel-body">
      <pre>$(printf '%s\n' "${SUBDOMAINS[@]}" 2>&1 | head -200 || echo 'None found')</pre>
    </div>
  </section>

  <!-- LIVE HOSTS -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>✅</span><h2>Live Hosts</h2><span class="badge">${#LIVE_HOSTS[@]}</span>
    </div>
    <div class="panel-body">
      <pre>$(printf '%s\n' "${LIVE_HOSTS[@]}" 2>&1 || echo 'None detected')</pre>
    </div>
  </section>

  <!-- DNS -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>🗺️</span><h2>DNS Records</h2>
    </div>
    <div class="panel-body">
      <pre>$(cat "${OUTPUT_DIR}/dns/dig_full.txt" 2>&1 | head -100 || echo 'No DNS data')</pre>
    </div>
  </section>

  <!-- TECHNOLOGIES -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>⚙️</span><h2>Technologies Detected</h2><span class="badge">${#TECHNOLOGIES[@]}</span>
    </div>
    <div class="panel-body">
      <pre>$(printf '%s\n' "${TECHNOLOGIES[@]}" 2>&1 || echo 'None detected')</pre>
    </div>
  </section>

  <!-- WAF -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>🛡️</span><h2>WAF Detection</h2>
    </div>
    <div class="panel-body">
      <pre>$(cat "${OUTPUT_DIR}/web/wafw00f.txt" 2>&1 || echo 'No WAF data')</pre>
    </div>
  </section>

  <!-- EMAILS -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>📧</span><h2>Emails & OSINT</h2><span class="badge">${#EMAILS[@]}</span>
    </div>
    <div class="panel-body">
      <pre>$(printf '%s\n' "${EMAILS[@]}" 2>&1 || echo 'None found')</pre>
    </div>
  </section>

  <!-- INTERESTING ENDPOINTS -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>🔎</span><h2>Interesting Endpoints</h2><span class="badge">${#ENDPOINTS[@]}</span>
    </div>
    <div class="panel-body">
      <pre>$(cat "${OUTPUT_DIR}/endpoints/endpoints_tagged.txt" 2>&1 | head -200 || echo 'None found')</pre>
    </div>
  </section>

  <!-- PARAMETERS -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>🔗</span><h2>Parameters</h2><span class="badge">${#PARAMS[@]}</span>
    </div>
    <div class="panel-body">
      <pre>$(printf '%s\n' "${PARAMS[@]}" 2>&1 | head -100 || echo 'None found')</pre>
    </div>
  </section>

  <!-- OPEN PORTS -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>🔌</span><h2>Open Ports & Services</h2><span class="badge">${#OPEN_PORTS[@]}</span>
    </div>
    <div class="panel-body">
      <pre>$(cat "${OUTPUT_DIR}/network/open_ports.txt" 2>&1 || echo 'No scan data / skipped')</pre>
    </div>
  </section>

  <!-- VULNERABILITIES -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>💀</span><h2>Vulnerabilities (nuclei)</h2><span class="badge">${#VULNS[@]}</span>
    </div>
    <div class="panel-body">
      <pre>$(cat "${OUTPUT_DIR}/network/nuclei_results.txt" 2>&1 | head -100 || echo 'No findings / skipped')</pre>
    </div>
  </section>

  <!-- GOOGLE DORKS -->
  <section class="panel">
    <div class="panel-header" onclick="toggle(this)">
      <span>🔍</span><h2>Google Dorks</h2>
    </div>
    <div class="panel-body">
      <pre>$(cat "${OUTPUT_DIR}/osint/google_dorks.txt" 2>&1)</pre>
    </div>
  </section>

</div>

<footer>CyberRecon V4 v${VERSION} &nbsp;|&nbsp; For Authorized Security Testing Only &nbsp;|&nbsp; $(date)</footer>

<script>
  function toggle(header) {
    const body = header.nextElementSibling;
    body.classList.toggle('hidden');
  }
</script>
</body>
</html>
HTML
}

# =============================================================================
#  TERMINAL RESULTS DISPLAY — Full Categorized Output
# =============================================================================

# ── Box drawing helpers ───────────────────────────────────────────────────────
_box_top()    { echo -e "  ${LBLUE}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"; }
_box_bottom() { echo -e "  ${LBLUE}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"; }
_box_sep()    { echo -e "  ${LBLUE}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"; }
_box_blank()  { echo -e "  ${LBLUE}║${RESET}$(printf '%-78s' '')${LBLUE}║${RESET}"; }

_box_title() {
  local title="$1" icon="${2:-}"
  local inner="${icon}  ${title}"
  local pad=$(( 76 - ${#inner} ))
  printf "  ${LBLUE}║${RESET}  ${WHITE}${BOLD}%s${RESET}$(printf '%-*s' $pad '')  ${LBLUE}║${RESET}\n" "${inner}"
}

_cat_header() {
  local num="$1" title="$2" icon="${3:-●}" count="${4:-}"
  local count_str=""
  [[ -n "$count" ]] && count_str="  ${DIM}(${count})${RESET}"
  echo ""
  echo -e "  ${MAGENTA}╔╦═══════════════════════════════════════════════════════════════════════╗${RESET}"
  printf   "  ${MAGENTA}║║${RESET}  ${icon}  ${WHITE}${BOLD}[%02d]  %-52s${RESET}%s  ${MAGENTA}║${RESET}\n" \
           "$num" "$title" "$count_str"
  echo -e "  ${MAGENTA}╚╩═══════════════════════════════════════════════════════════════════════╝${RESET}"
}

_row() {
  # _row "label" "value" [color]
  local lbl="$1" val="$2" col="${3:-$WHITE}"
  printf "  ${CYAN}│${RESET}  ${GRAY}%-22s${RESET}${col}%s${RESET}\n" "$lbl" "$val"
}

_divider() {
  echo -e "  ${DIM}${CYAN}  ─────────────────────────────────────────────────────────────────────────${RESET}"
}

_entry()     { echo -e "  ${GREEN}  ►${RESET}  $*"; }
_entry_hi()  { echo -e "  ${LRED}  ►${RESET}  $*"; }
_entry_med() { echo -e "  ${YELLOW}  ►${RESET}  $*"; }
_entry_low() { echo -e "  ${GREEN}  ►${RESET}  $*"; }
_entry_dim() { echo -e "  ${GRAY}  ·${RESET}  ${DIM}$*${RESET}"; }

_tag_high()     { echo -e "${LRED}[HIGH]${RESET}"; }
_tag_med()      { echo -e "${YELLOW}[MED] ${RESET}"; }
_tag_low()      { echo -e "${GREEN}[LOW] ${RESET}"; }
_tag_critical() { echo -e "${BLINK}${LRED}[CRIT]${RESET}"; }
_tag_info()     { echo -e "${CYAN}[INFO]${RESET}"; }

# ── Pager for long lists ──────────────────────────────────────────────────────
_show_list() {
  # _show_list <array_ref_name> <max_display> <empty_msg>
  local -n _arr=$1
  local max="${2:-50}"
  local empty_msg="${3:-None found}"
  local total=${#_arr[@]}

  if [[ $total -eq 0 ]]; then
    echo -e "  ${GRAY}  ${empty_msg}${RESET}"
    return
  fi

  local shown=0
  for item in "${_arr[@]}"; do
    [[ $shown -ge $max ]] && break
    echo -e "  ${DIM}${CYAN}  [$(printf '%04d' $((shown+1)))]${RESET}  ${item}"
    shown=$(( shown + 1 ))
  done

  if [[ $total -gt $max ]]; then
    echo ""
    echo -e "  ${YELLOW}  … and $(( total - max )) more. See full list in: ${CYAN}${OUTPUT_DIR}${RESET}"
  fi
}

# =============================================================================
display_terminal_results() {
  local end_time=$(date +%s)
  local duration=$(( end_time - START_TIME ))
  local mins=$(( duration / 60 ))
  local secs=$(( duration % 60 ))
  local ip_addr
  ip_addr=$(dig A "$TARGET" +short 2>&1 | head -1 || echo "N/A")

  # ── Master header ──────────────────────────────────────────────────────────
  clear
  echo ""
  echo -e "${LRED}"
  cat << 'HDR'
  ╔═══════════════════════════════════════════════════════════════════════════════╗
  ║        ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗ ██████╗     ║
  ║       ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝     ║
  ║       ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝█████╗  ██║          ║
  ║       ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║          ║
  ║       ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║███████╗╚██████╗     ║
  ║        ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝     ║
  ╠═══════════════════════════════════════════════════════════════════════════════╣
  ║            COMPLETE RECONNAISSANCE RESULTS — TERMINAL OUTPUT                 ║
  ╚═══════════════════════════════════════════════════════════════════════════════╝
HDR
  echo -e "${RESET}"

  # ── Metadata bar ──────────────────────────────────────────────────────────
  echo -e "  ${BOLD}${WHITE}  Target  :${RESET} ${LCYAN}${TARGET}${RESET}   ${BOLD}${WHITE}IP :${RESET} ${ip_addr}   ${BOLD}${WHITE}Type :${RESET} ${TARGET_TYPE}   ${BOLD}${WHITE}Time :${RESET} ${mins}m ${secs}s"
  echo -e "  ${BOLD}${WHITE}  Output  :${RESET} ${DIM}${OUTPUT_DIR}${RESET}"
  _divider
  echo ""

  # ── Quick stats row ────────────────────────────────────────────────────────
  echo -e "  ${BOLD}${LBLUE}  QUICK STATS${RESET}"
  echo ""
  printf "  "
  printf "${CYAN}┌─────────────────┬──────────┐${RESET}  "
  printf "${CYAN}┌─────────────────┬──────────┐${RESET}  "
  printf "${CYAN}┌─────────────────┬──────────┐${RESET}  "
  printf "${CYAN}┌─────────────────┬──────────┐${RESET}\n"

  printf "  "
  printf "${CYAN}│${RESET} ${WHITE}%-15s${RESET} ${CYAN}│${RESET} ${LGREEN}%8s${RESET} ${CYAN}│${RESET}  " "Subdomains"    "${#SUBDOMAINS[@]}"
  printf "${CYAN}│${RESET} ${WHITE}%-15s${RESET} ${CYAN}│${RESET} ${LGREEN}%8s${RESET} ${CYAN}│${RESET}  " "Live Hosts"    "${#LIVE_HOSTS[@]}"
  printf "${CYAN}│${RESET} ${WHITE}%-15s${RESET} ${CYAN}│${RESET} ${LGREEN}%8s${RESET} ${CYAN}│${RESET}  " "Emails"        "${#EMAILS[@]}"
  printf "${CYAN}│${RESET} ${WHITE}%-15s${RESET} ${CYAN}│${RESET} ${YELLOW}%8s${RESET} ${CYAN}│${RESET}\n"  "Open Ports"   "${#OPEN_PORTS[@]}"

  printf "  "
  printf "${CYAN}└─────────────────┴──────────┘${RESET}  "
  printf "${CYAN}└─────────────────┴──────────┘${RESET}  "
  printf "${CYAN}└─────────────────┴──────────┘${RESET}  "
  printf "${CYAN}└─────────────────┴──────────┘${RESET}\n"
  echo ""

  printf "  "
  printf "${CYAN}┌─────────────────┬──────────┐${RESET}  "
  printf "${CYAN}┌─────────────────┬──────────┐${RESET}  "
  printf "${CYAN}┌─────────────────┬──────────┐${RESET}  "
  printf "${CYAN}┌─────────────────┬──────────┐${RESET}\n"

  printf "  "
  printf "${CYAN}│${RESET} ${WHITE}%-15s${RESET} ${CYAN}│${RESET} ${LGREEN}%8s${RESET} ${CYAN}│${RESET}  " "Total URLs"    "${#URLS[@]}"
  printf "${CYAN}│${RESET} ${WHITE}%-15s${RESET} ${CYAN}│${RESET} ${LGREEN}%8s${RESET} ${CYAN}│${RESET}  " "Parameters"    "${#PARAMS[@]}"
  printf "${CYAN}│${RESET} ${WHITE}%-15s${RESET} ${CYAN}│${RESET} ${LGREEN}%8s${RESET} ${CYAN}│${RESET}  " "Endpoints"     "${#ENDPOINTS[@]}"
  printf "${CYAN}│${RESET} ${WHITE}%-15s${RESET} ${CYAN}│${RESET} ${LRED}%8s${RESET} ${CYAN}│${RESET}\n"  "Vulns Found"  "${#VULNS[@]}"

  printf "  "
  printf "${CYAN}└─────────────────┴──────────┘${RESET}  "
  printf "${CYAN}└─────────────────┴──────────┘${RESET}  "
  printf "${CYAN}└─────────────────┴──────────┘${RESET}  "
  printf "${CYAN}└─────────────────┴──────────┘${RESET}\n"

  echo ""
  echo ""
  echo -e "  ${YELLOW}  Press ${WHITE}[ENTER]${YELLOW} to scroll through all categories...${RESET}"
  read -r _dummy || true

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 01 — TARGET SUMMARY
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 1 "TARGET SUMMARY" "🎯"
  echo ""
  _row "Target"         "${TARGET}"       "$LCYAN"
  _row "Type"           "${TARGET_TYPE}"  "$WHITE"
  _row "IP Address"     "${ip_addr}"      "$LGREEN"
  _row "Scan Date"      "$(date)"         "$GRAY"
  _row "Duration"       "${mins}m ${secs}s" "$WHITE"
  _row "Output Dir"     "${OUTPUT_DIR}"   "$CYAN"
  _row "Passive Only"   "${PASSIVE_ONLY}" "$GRAY"
  _row "Active Only"    "${ACTIVE_ONLY}"  "$GRAY"
  _row "Nuclei Sev"     "${NUCLEI_SEVERITY}" "$YELLOW"
  _row "Threads"        "${THREADS}"      "$GRAY"
  echo ""

  # Whois key fields
  if [[ -f "${OUTPUT_DIR}/osint/whois.txt" ]]; then
    _divider
    echo -e "  ${LBLUE}  WHOIS Highlights:${RESET}"
    local whois_fields=("Registrar:" "Registrant" "Creation Date:" "Updated Date:" "Expiry Date:" "Name Server:" "DNSSEC:")
    for field in "${whois_fields[@]}"; do
      local val
      val=$(grep -i "^${field}" "${OUTPUT_DIR}/osint/whois.txt" 2>&1 | head -1 | sed 's/^[^:]*: *//')
      [[ -n "$val" ]] && _row "  $field" "$val" "$GRAY"
    done
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 02 — SUBDOMAINS
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 2 "SUBDOMAINS" "🌐" "${#SUBDOMAINS[@]} unique"
  echo ""

  if [[ ${#SUBDOMAINS[@]} -eq 0 ]]; then
    echo -e "  ${GRAY}  No subdomains found.${RESET}"
  else
    # Column layout — 3 columns
    local col_w=35
    local cols=3
    local idx=0
    local total_sub=${#SUBDOMAINS[@]}
    printf "  "
    for sub in "${SUBDOMAINS[@]}"; do
      printf "${CYAN}%-${col_w}s${RESET}" "$sub"
      idx=$(( idx + 1 ))
      if (( idx % cols == 0 )); then
        echo ""
        printf "  "
      fi
    done
    [[ $(( total_sub % cols )) -ne 0 ]] && echo ""

    if [[ $total_sub -gt 150 ]]; then
      echo ""
      echo -e "  ${YELLOW}  … ${total_sub} total. Full list: ${CYAN}${OUTPUT_DIR}/passive/subdomains_all.txt${RESET}"
    fi
  fi
  echo ""

  # Source breakdown
  _divider
  echo -e "  ${LBLUE}  Source Breakdown:${RESET}"
  local s3r_cnt=0 crt_cnt=0 otx_cnt=0
  [[ -f "${OUTPUT_DIR}/passive/sublist3r.txt" ]] && s3r_cnt=$(wc -l < "${OUTPUT_DIR}/passive/sublist3r.txt" 2>&1 || echo 0)
  [[ -f "${OUTPUT_DIR}/passive/crtsh.txt"     ]] && crt_cnt=$(wc -l < "${OUTPUT_DIR}/passive/crtsh.txt"    2>&1 || echo 0)
  [[ -f "${OUTPUT_DIR}/passive/otx_dns.txt"   ]] && otx_cnt=$(wc -l < "${OUTPUT_DIR}/passive/otx_dns.txt"  2>&1 || echo 0)
  _row "  Sublist3r"  "${s3r_cnt} subdomains" "$LGREEN"
  _row "  crt.sh"     "${crt_cnt} subdomains" "$LGREEN"
  _row "  AlienVault" "${otx_cnt} subdomains" "$LGREEN"
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 03 — LIVE HOSTS
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 3 "LIVE HOSTS" "✅" "${#LIVE_HOSTS[@]} responding"
  echo ""

  if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
    echo -e "  ${GRAY}  No live hosts detected.${RESET}"
  else
    # Try to pull status codes from httpx json
    if [[ -f "${OUTPUT_DIR}/active/httpx.json" ]]; then
      printf "  ${CYAN}  %-50s  %-8s  %-6s  %s${RESET}\n" "URL" "STATUS" "CODE" "TITLE"
      _divider
      while IFS= read -r jsonline; do
        local url status_code title
        url=$(echo "$jsonline"   | grep -oP '"url":\s*"\K[^"]+' 2>&1 || echo "")
        status_code=$(echo "$jsonline" | grep -oP '"status_code":\s*\K\d+' 2>&1 || echo "")
        title=$(echo "$jsonline" | grep -oP '"title":\s*"\K[^"]+' 2>&1 | head -c 40 || echo "")

        [[ -z "$url" ]] && continue

        local col="$WHITE"
        local sc_col="$GRAY"
        case "$status_code" in
          200)         sc_col="$LGREEN" ;;
          201|204)     sc_col="$GREEN"  ;;
          301|302|303) sc_col="$YELLOW" ;;
          401|403)     sc_col="$YELLOW" ;;
          404)         sc_col="$GRAY"   ;;
          500|502|503) sc_col="$LRED"   ;;
        esac

        printf "  ${GREEN}  ►${RESET}  ${WHITE}%-50s${RESET}  ${sc_col}%-8s${RESET}  ${GRAY}%s${RESET}\n" \
               "${url:0:50}" "$status_code" "$title"
      done < "${OUTPUT_DIR}/active/httpx.json" 2>&1 | head -80 || true
    else
      _show_list LIVE_HOSTS 60 "No live hosts"
    fi
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 04 — DNS RECORDS
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 4 "DNS RECORDS" "🗺️"
  echo ""

  # ── A Records ────────────────────────────────────────────────────────────
  echo -e "  ${BOLD}${WHITE}  ▌ A Records (IPv4)${RESET}"
  dig A "$TARGET" +short 2>&1 | while read -r ip; do
    _entry "${WHITE}A${RESET}    →  ${LGREEN}${ip}${RESET}"
  done || true

  # ── AAAA Records ──────────────────────────────────────────────────────────
  local aaaa_out
  aaaa_out=$(dig AAAA "$TARGET" +short 2>&1 || true)
  if [[ -n "$aaaa_out" ]]; then
    echo -e "\n  ${BOLD}${WHITE}  ▌ AAAA Records (IPv6)${RESET}"
    echo "$aaaa_out" | while read -r ip6; do
      _entry "${CYAN}AAAA${RESET} →  ${LGREEN}${ip6}${RESET}"
    done
  fi

  # ── MX Records ────────────────────────────────────────────────────────────
  echo -e "\n  ${BOLD}${WHITE}  ▌ MX Records (Mail Servers)${RESET}"
  dig MX "$TARGET" +short 2>&1 | sort -n | while read -r prio mx; do
    _entry "${YELLOW}MX${RESET}   →  ${WHITE}${mx}${RESET}  ${DIM}(priority: ${prio})${RESET}"
  done || _entry_dim "No MX records"

  # ── NS Records ────────────────────────────────────────────────────────────
  echo -e "\n  ${BOLD}${WHITE}  ▌ NS Records (Name Servers)${RESET}"
  dig NS "$TARGET" +short 2>&1 | while read -r ns; do
    _entry "${CYAN}NS${RESET}   →  ${WHITE}${ns}${RESET}"
  done || _entry_dim "No NS records"

  # ── TXT Records ───────────────────────────────────────────────────────────
  echo -e "\n  ${BOLD}${WHITE}  ▌ TXT Records (SPF / DKIM / DMARC / Verification)${RESET}"
  dig TXT "$TARGET" +short 2>&1 | while IFS= read -r txt; do
    if echo "$txt" | grep -qi "v=spf"; then
      _entry "${GREEN}SPF${RESET}   →  ${txt}"
    elif echo "$txt" | grep -qi "v=DMARC"; then
      _entry "${GREEN}DMARC${RESET} →  ${txt}"
    elif echo "$txt" | grep -qi "v=DKIM"; then
      _entry "${GREEN}DKIM${RESET}  →  ${txt}"
    else
      _entry_dim "TXT   →  ${txt}"
    fi
  done || _entry_dim "No TXT records"

  # ── SOA Record ────────────────────────────────────────────────────────────
  echo -e "\n  ${BOLD}${WHITE}  ▌ SOA Record${RESET}"
  dig SOA "$TARGET" +short 2>&1 | while IFS= read -r soa; do
    _entry "${MAGENTA}SOA${RESET}  →  ${soa}"
  done || _entry_dim "No SOA record"

  # ── AXFR result ───────────────────────────────────────────────────────────
  echo -e "\n  ${BOLD}${WHITE}  ▌ Zone Transfer (AXFR)${RESET}"
  if grep -qi "zone transfer" "${OUTPUT_DIR}/dns/dnsrecon_axfr.txt" 2>&1; then
    echo -e "  ${LRED}  ⚠  ZONE TRANSFER SUCCESSFUL — CRITICAL MISCONFIGURATION!${RESET}"
    head -20 "${OUTPUT_DIR}/dns/dnsrecon_axfr.txt" 2>&1 | while IFS= read -r l; do
      echo -e "    ${LRED}${l}${RESET}"
    done
  else
    _entry_dim "Zone transfer not allowed (expected)"
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 05 — TECHNOLOGIES DETECTED
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 5 "TECHNOLOGIES DETECTED" "⚙️" "${#TECHNOLOGIES[@]} detected"
  echo ""

  if [[ ${#TECHNOLOGIES[@]} -eq 0 ]]; then
    echo -e "  ${GRAY}  No technologies detected.${RESET}"
  else
    # Group by category keywords
    local cms_list=() server_list=() lang_list=() js_list=() sec_list=() other_list=()
    for tech in "${TECHNOLOGIES[@]}"; do
      if echo "$tech" | grep -qiE 'WordPress|Joomla|Drupal|Magento|Shopify|Ghost|Wix|Squarespace'; then
        cms_list+=("$tech")
      elif echo "$tech" | grep -qiE 'Apache|Nginx|IIS|LiteSpeed|Caddy|Tomcat'; then
        server_list+=("$tech")
      elif echo "$tech" | grep -qiE 'PHP|Python|Ruby|Java|Node|Go|Perl|ASP'; then
        lang_list+=("$tech")
      elif echo "$tech" | grep -qiE 'jQuery|React|Vue|Angular|Bootstrap|Tailwind|Next'; then
        js_list+=("$tech")
      elif echo "$tech" | grep -qiE 'Cloudflare|SSL|TLS|WAF|reCAPTCHA|HSTS'; then
        sec_list+=("$tech")
      else
        other_list+=("$tech")
      fi
    done

    [[ ${#cms_list[@]}    -gt 0 ]] && { echo -e "  ${BOLD}${YELLOW}  ▌ CMS / Platforms${RESET}";    for t in "${cms_list[@]}";    do _entry "  ${YELLOW}${t}${RESET}"; done; echo ""; }
    [[ ${#server_list[@]} -gt 0 ]] && { echo -e "  ${BOLD}${GREEN}  ▌ Web Servers${RESET}";         for t in "${server_list[@]}"; do _entry "  ${GREEN}${t}${RESET}";  done; echo ""; }
    [[ ${#lang_list[@]}   -gt 0 ]] && { echo -e "  ${BOLD}${CYAN}  ▌ Languages / Frameworks${RESET}"; for t in "${lang_list[@]}";   do _entry "  ${CYAN}${t}${RESET}";   done; echo ""; }
    [[ ${#js_list[@]}     -gt 0 ]] && { echo -e "  ${BOLD}${LBLUE}  ▌ JS Libraries / UI${RESET}";  for t in "${js_list[@]}";     do _entry "  ${LBLUE}${t}${RESET}";  done; echo ""; }
    [[ ${#sec_list[@]}    -gt 0 ]] && { echo -e "  ${BOLD}${MAGENTA}  ▌ Security / CDN${RESET}";    for t in "${sec_list[@]}";    do _entry "  ${MAGENTA}${t}${RESET}"; done; echo ""; }
    [[ ${#other_list[@]}  -gt 0 ]] && { echo -e "  ${BOLD}${GRAY}  ▌ Other${RESET}";               for t in "${other_list[@]}";  do _entry_dim "  ${t}"; done; echo ""; }
  fi

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 06 — WAF DETECTION
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 6 "WAF DETECTION" "🛡️"
  echo ""

  if [[ -f "${OUTPUT_DIR}/web/wafw00f.txt" ]]; then
    if grep -qi "is behind" "${OUTPUT_DIR}/web/wafw00f.txt" 2>&1; then
      local waf_line
      waf_line=$(grep -i "is behind" "${OUTPUT_DIR}/web/wafw00f.txt" | head -3)
      echo -e "  ${YELLOW}  ⚠  WAF DETECTED:${RESET}"
      echo "$waf_line" | while IFS= read -r wl; do
        _entry_med "  ${YELLOW}${wl}${RESET}"
      done
      echo ""
      echo -e "  ${DIM}  Implication: Payloads may be filtered. Consider WAF bypass techniques.${RESET}"
    elif grep -qi "No WAF\|not behind" "${OUTPUT_DIR}/web/wafw00f.txt" 2>&1; then
      echo -e "  ${GREEN}  ✔  No WAF detected — Direct access likely${RESET}"
      _entry_low "  ${GREEN}No firewall between you and the application${RESET}"
    else
      cat "${OUTPUT_DIR}/web/wafw00f.txt" 2>&1 | while IFS= read -r l; do
        [[ -n "$l" ]] && _entry_dim "$l"
      done || true
    fi
  else
    echo -e "  ${GRAY}  WAF scan not run.${RESET}"
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 07 — EMAILS & OSINT
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 7 "EMAILS & OSINT" "📧" "${#EMAILS[@]} emails"
  echo ""

  if [[ ${#EMAILS[@]} -eq 0 ]]; then
    echo -e "  ${GRAY}  No emails found.${RESET}"
  else
    printf "  ${CYAN}  %-40s  %s${RESET}\n" "EMAIL ADDRESS" "SOURCE / STATUS"
    _divider
    for email in "${EMAILS[@]}"; do
      local breached=""
      [[ -f "${OUTPUT_DIR}/osint/hibp_breaches.txt" ]] && \
        grep -q "$email" "${OUTPUT_DIR}/osint/hibp_breaches.txt" 2>&1 && \
        breached="${LRED}  ⚠ BREACHED${RESET}"

      printf "  ${GREEN}  ►${RESET}  ${WHITE}%-40s${RESET}%b\n" "$email" "$breached"
    done
  fi

  # HIBP summary
  if [[ -f "${OUTPUT_DIR}/osint/hibp_breaches.txt" ]]; then
    echo ""
    _divider
    echo -e "  ${LRED}  HaveIBeenPwned Breaches:${RESET}"
    while IFS= read -r bl; do
      _entry_hi "  ${bl}"
    done < "${OUTPUT_DIR}/osint/hibp_breaches.txt" 2>&1 | head -20 || true
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 08 — HISTORICAL URLS (Wayback Machine)
  # ════════════════════════════════════════════════════════════════════════════
  local wb_total=0
  [[ -f "${OUTPUT_DIR}/active/wayback_urls.txt" ]] && \
    wb_total=$(wc -l < "${OUTPUT_DIR}/active/wayback_urls.txt" 2>&1 || echo 0)

  _cat_header 8 "HISTORICAL URLs (Wayback Machine)" "⏳" "${wb_total} total"
  echo ""

  if [[ "$wb_total" -eq 0 ]]; then
    echo -e "  ${GRAY}  No historical URLs found.${RESET}"
  else
    echo -e "  ${DIM}  Showing top 60 — full list at: ${OUTPUT_DIR}/active/wayback_urls.txt${RESET}"
    echo ""

    # Group by extension type
    local static_urls=() api_urls=() param_urls=() php_urls=() other_urls=()
    while IFS= read -r url; do
      if echo "$url" | grep -qE '\.(js|css|jpg|png|gif|ico|svg|woff|ttf)(\?|$)'; then
        static_urls+=("$url")
      elif echo "$url" | grep -qE '/api/|/v[0-9]/|graphql|swagger'; then
        api_urls+=("$url")
      elif echo "$url" | grep -q '?'; then
        param_urls+=("$url")
      elif echo "$url" | grep -qE '\.php(\?|$)'; then
        php_urls+=("$url")
      else
        other_urls+=("$url")
      fi
    done < "${OUTPUT_DIR}/active/wayback_urls.txt" 2>&1 || true

    [[ ${#api_urls[@]}   -gt 0 ]] && { echo -e "  ${BOLD}${LRED}  ▌ API Endpoints (${#api_urls[@]})${RESET}";   printf '%s\n' "${api_urls[@]:0:15}"   | sed 's/^/     /'; echo ""; }
    [[ ${#param_urls[@]} -gt 0 ]] && { echo -e "  ${BOLD}${YELLOW}  ▌ Parameterized URLs (${#param_urls[@]})${RESET}"; printf '%s\n' "${param_urls[@]:0:15}" | sed 's/^/     /'; echo ""; }
    [[ ${#php_urls[@]}   -gt 0 ]] && { echo -e "  ${BOLD}${CYAN}  ▌ PHP Pages (${#php_urls[@]})${RESET}";        printf '%s\n' "${php_urls[@]:0:15}"   | sed 's/^/     /'; echo ""; }
    [[ ${#other_urls[@]} -gt 0 ]] && { echo -e "  ${BOLD}${GRAY}  ▌ Other Pages (${#other_urls[@]})${RESET}";    printf '%s\n' "${other_urls[@]:0:15}"  | sed 's/^/     /'; echo ""; }
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 09 — PARAMETERS
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 9 "URL PARAMETERS (Filtered)" "🔗" "${#PARAMS[@]} unique"
  echo ""

  if [[ ${#PARAMS[@]} -eq 0 ]]; then
    echo -e "  ${GRAY}  No parameters found.${RESET}"
  else
    # Tag interesting params
    local sqli_params=() xss_params=() idor_params=() redirect_params=() file_params=() other_params=()
    for p in "${PARAMS[@]}"; do
      local pl
      pl=$(echo "$p" | tr '[:upper:]' '[:lower:]')
      if echo "$pl" | grep -qE '^(id|user_id|userid|uid|account|order|item|product|invoice|num|ref)$'; then
        idor_params+=("$p")
      elif echo "$pl" | grep -qE '^(url|redirect|return|next|to|goto|dest|destination|redir|redirect_uri)$'; then
        redirect_params+=("$p")
      elif echo "$pl" | grep -qE '^(file|path|filename|dir|folder|include|page|template|load|read)$'; then
        file_params+=("$p")
      elif echo "$pl" | grep -qE '^(q|query|search|s|keyword|term|find|name|input|text|comment|msg|message)$'; then
        xss_params+=("$p")
      elif echo "$pl" | grep -qE '^(id|select|from|where|order|limit|table|col|column|sort|filter)$'; then
        sqli_params+=("$p")
      else
        other_params+=("$p")
      fi
    done

    [[ ${#idor_params[@]}    -gt 0 ]] && {
      echo -e "  ${BOLD}${LRED}  ▌ Potential IDOR Params ${DIM}(test with different IDs)${RESET}"
      printf "    "; printf "${LRED}%-20s  ${RESET}" "${idor_params[@]}"; echo ""
      echo ""
    }
    [[ ${#redirect_params[@]} -gt 0 ]] && {
      echo -e "  ${BOLD}${YELLOW}  ▌ Open Redirect Candidates${RESET}"
      printf "    "; printf "${YELLOW}%-20s  ${RESET}" "${redirect_params[@]}"; echo ""
      echo ""
    }
    [[ ${#file_params[@]}    -gt 0 ]] && {
      echo -e "  ${BOLD}${LRED}  ▌ File / Path Inclusion Candidates${RESET}"
      printf "    "; printf "${LRED}%-20s  ${RESET}" "${file_params[@]}"; echo ""
      echo ""
    }
    [[ ${#xss_params[@]}     -gt 0 ]] && {
      echo -e "  ${BOLD}${YELLOW}  ▌ XSS / Injection Candidates${RESET}"
      printf "    "; printf "${YELLOW}%-20s  ${RESET}" "${xss_params[@]}"; echo ""
      echo ""
    }
    [[ ${#other_params[@]}   -gt 0 ]] && {
      echo -e "  ${BOLD}${GRAY}  ▌ Other Parameters${RESET}"
      local col=0
      for p in "${other_params[@]:0:60}"; do
        printf "    ${GRAY}%-22s${RESET}" "$p"
        col=$(( col + 1 ))
        (( col % 4 == 0 )) && { echo ""; printf ""; }
      done
      echo ""
    }
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 10 — INTERESTING ENDPOINTS
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 10 "INTERESTING ENDPOINTS" "🔎" "${#ENDPOINTS[@]} found"
  echo ""

  if [[ ${#ENDPOINTS[@]} -eq 0 ]]; then
    echo -e "  ${GRAY}  No interesting endpoints found.${RESET}"
  else
    printf "  ${CYAN}  %-10s  %-8s  %s${RESET}\n" "SEVERITY" "TYPE" "ENDPOINT"
    _divider

    local high_patt='\.env|\.git|backup|passwd|id_rsa|credentials|token|secret|s3\.|\.sql|\.pem|\.key'
    local med_patt='login|dashboard|api/|swagger|graphql|config|wp-admin|phpmyadmin|actuator|\.bak|setup|install'

    local shown_count=0
    while IFS= read -r ep; do
      [[ $shown_count -ge 80 ]] && break
      local sev_tag type_tag color

      if echo "$ep" | grep -qiE "$high_patt"; then
        sev_tag="[HIGH]  "; color="$LRED"
        if   echo "$ep" | grep -qi '\.env';                          then type_tag="ENV-FILE "
        elif echo "$ep" | grep -qi '\.git';                          then type_tag="GIT      "
        elif echo "$ep" | grep -qiE 'backup|\.bak|\.sql';            then type_tag="BACKUP   "
        elif echo "$ep" | grep -qiE 'secret|token|credential|key';   then type_tag="SECRET   "
        elif echo "$ep" | grep -qi 's3\.';                           then type_tag="S3-BUCKET"
        else                                                               type_tag="SENSITIVE"
        fi
      elif echo "$ep" | grep -qiE "$med_patt"; then
        sev_tag="[MED]   "; color="$YELLOW"
        if   echo "$ep" | grep -qi 'swagger\|graphql';               then type_tag="API-DOCS "
        elif echo "$ep" | grep -qiE 'admin|wp-admin|phpmyadmin';     then type_tag="ADMIN    "
        elif echo "$ep" | grep -qi 'login';                          then type_tag="AUTH     "
        elif echo "$ep" | grep -qi 'actuator';                       then type_tag="ACTUATOR "
        else                                                               type_tag="WEB      "
        fi
      else
        sev_tag="[LOW]   "; color="$GREEN"
        type_tag="INFO     "
      fi

      printf "  ${color}  ►  %-9s${RESET}  ${DIM}%-10s${RESET}  ${WHITE}%s${RESET}\n" \
             "$sev_tag" "$type_tag" "${ep:0:90}"
      shown_count=$(( shown_count + 1 ))
    done < "${OUTPUT_DIR}/endpoints/interesting_endpoints.txt" 2>&1 || true

    if [[ ${#ENDPOINTS[@]} -gt 80 ]]; then
      echo ""
      echo -e "  ${YELLOW}  … ${#ENDPOINTS[@]} total. Full list: ${CYAN}${OUTPUT_DIR}/endpoints/interesting_endpoints.txt${RESET}"
    fi
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 11 — OPEN PORTS & SERVICES
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 11 "OPEN PORTS & SERVICES" "🔌" "${#OPEN_PORTS[@]} open"
  echo ""

  if [[ ${#OPEN_PORTS[@]} -eq 0 ]]; then
    echo -e "  ${GRAY}  No port data (nmap may have been skipped).${RESET}"
  else
    printf "  ${CYAN}  %-8s  %-12s  %-18s  %s${RESET}\n" "PORT" "STATE" "SERVICE" "VERSION"
    _divider

    local danger_services='ms-sql-s|rdp|telnet|ftp|smb|vnc|redis|mongod|mysql|postgres|elasticsearch|memcached|cassandra|couch'
    local notable_ports='21 22 23 25 53 110 111 135 139 143 445 1433 1521 3306 3389 5432 5900 6379 8080 8443 8888 27017 9200 11211'

    for port_line in "${OPEN_PORTS[@]}"; do
      local port proto state service version
      port=$(echo "$port_line"    | awk '{print $1}' | cut -d/ -f1)
      proto=$(echo "$port_line"   | awk '{print $1}' | cut -d/ -f2)
      state=$(echo "$port_line"   | awk '{print $2}')
      service=$(echo "$port_line" | awk '{print $3}')
      version=$(echo "$port_line" | awk '{$1=$2=$3=""; print}' | sed 's/^ *//' | head -c 50)

      local row_color="$WHITE"
      local flag=""

      if echo "$service $version" | grep -qiE "$danger_services"; then
        row_color="$LRED"
        flag="  ${LRED}⚠  DANGEROUS SERVICE${RESET}"
      elif echo "$notable_ports" | grep -qw "$port"; then
        row_color="$YELLOW"
        flag="  ${YELLOW}★  NOTABLE${RESET}"
      fi

      printf "  ${row_color}  ►  %-8s  %-12s  %-18s  %-50s${RESET}%b\n" \
             "${port}/${proto}" "$state" "$service" "$version" "$flag"
    done
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 12 — VULNERABILITIES (nuclei)
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 12 "VULNERABILITIES — nuclei Findings" "💀" "${#VULNS[@]} findings"
  echo ""

  if [[ ${#VULNS[@]} -eq 0 ]]; then
    echo -e "  ${GREEN}  ✔  No vulnerabilities found${RESET}  ${DIM}(or nuclei was skipped)${RESET}"
  else
    printf "  ${CYAN}  %-10s  %-35s  %s${RESET}\n" "SEVERITY" "TEMPLATE ID" "TARGET"
    _divider

    local crit_count=0 high_count=0 med_count=0 low_count=0 info_count=0

    for vuln in "${VULNS[@]}"; do
      local sev tid url_t
      sev=$(echo "$vuln"  | grep -oP '\[(critical|high|medium|low|info)\]' -i | tr -d '[]' | tr '[:lower:]' '[:upper:]' || echo "INFO")
      tid=$(echo "$vuln"  | grep -oP '\[[\w-]+\]' | head -1 | tr -d '[]' || echo "unknown")
      url_t=$(echo "$vuln" | grep -oP 'https?://[^\s]+' | head -1 || echo "")

      local sev_color="$GRAY"
      case "${sev,,}" in
        critical) sev_color="$BLINK$LRED";   crit_count=$(( crit_count + 1 )) ;;
        high)     sev_color="$LRED";          high_count=$(( high_count + 1 )) ;;
        medium)   sev_color="$YELLOW";        med_count=$(( med_count + 1 ))   ;;
        low)      sev_color="$GREEN";         low_count=$(( low_count + 1 ))   ;;
        info)     sev_color="$CYAN";          info_count=$(( info_count + 1 )) ;;
      esac

      printf "  ${sev_color}  ►  %-10s${RESET}  ${WHITE}%-35s${RESET}  ${DIM}%s${RESET}\n" \
             "[$sev]" "$tid" "${url_t:0:70}"
    done

    echo ""
    _divider
    echo -e "  ${BOLD}${WHITE}  Breakdown:${RESET}"
    [[ $crit_count -gt 0 ]] && echo -e "    ${LRED}  CRITICAL : ${crit_count}${RESET}"
    [[ $high_count -gt 0 ]] && echo -e "    ${RED}  HIGH     : ${high_count}${RESET}"
    [[ $med_count  -gt 0 ]] && echo -e "    ${YELLOW}  MEDIUM   : ${med_count}${RESET}"
    [[ $low_count  -gt 0 ]] && echo -e "    ${GREEN}  LOW      : ${low_count}${RESET}"
    [[ $info_count -gt 0 ]] && echo -e "    ${CYAN}  INFO     : ${info_count}${RESET}"
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 13 — GOOGLE DORKS
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 13 "GOOGLE DORKS (Auto-Generated)" "🔍"
  echo ""

  if [[ -f "${OUTPUT_DIR}/osint/google_dorks.txt" ]]; then
    echo -e "  ${DIM}  Copy and paste these into Google / DuckDuckGo / Bing${RESET}"
    echo ""

    local current_section=""
    while IFS= read -r dline; do
      if [[ "$dline" == "# ──"* ]] || [[ "$dline" == "#  ──"* ]]; then
        echo ""
        echo -e "  ${BOLD}${YELLOW}${dline/# /}${RESET}"
      elif [[ "$dline" == "#"* ]]; then
        echo -e "  ${DIM}${dline}${RESET}"
      elif [[ -n "$dline" ]]; then
        echo -e "  ${CYAN}  ►${RESET}  ${WHITE}${dline}${RESET}"
      fi
    done < "${OUTPUT_DIR}/osint/google_dorks.txt"
  else
    echo -e "  ${GRAY}  No dorks generated.${RESET}"
  fi
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 14 — ATTACK SURFACE OVERVIEW
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 14 "ATTACK SURFACE OVERVIEW" "⚔️"
  echo ""

  # Risk scoring
  local risk_score=0
  local risk_factors=()

  [[ ${#VULNS[@]} -gt 0 ]]      && { risk_score=$(( risk_score + 40 )); risk_factors+=("Active vulnerabilities detected (+40)"); }
  [[ ${#OPEN_PORTS[@]} -gt 10 ]] && { risk_score=$(( risk_score + 15 )); risk_factors+=("High number of open ports (+15)"); }
  [[ ${#WAFS[@]} -eq 0 ]] && command -v wafw00f &>/dev/null && \
    grep -qi "No WAF\|not behind" "${OUTPUT_DIR}/web/wafw00f.txt" 2>&1 && \
    { risk_score=$(( risk_score + 10 )); risk_factors+=("No WAF protection (+10)"); }
  [[ -f "${OUTPUT_DIR}/osint/hibp_breaches.txt" ]] && [[ -s "${OUTPUT_DIR}/osint/hibp_breaches.txt" ]] && \
    { risk_score=$(( risk_score + 20 )); risk_factors+=("Breached credentials found (+20)"); }
  [[ ${#ENDPOINTS[@]} -gt 20 ]] && { risk_score=$(( risk_score + 10 )); risk_factors+=("Large attack surface > 20 endpoints (+10)"); }
  grep -qi "zone transfer" "${OUTPUT_DIR}/dns/dnsrecon_axfr.txt" 2>&1 && \
    { risk_score=$(( risk_score + 25 )); risk_factors+=("DNS Zone Transfer allowed (+25)"); }

  # Cap at 100
  [[ $risk_score -gt 100 ]] && risk_score=100

  # Risk meter
  local risk_label risk_color
  if   [[ $risk_score -ge 80 ]]; then risk_label="CRITICAL";     risk_color="$LRED"
  elif [[ $risk_score -ge 60 ]]; then risk_label="HIGH";         risk_color="$RED"
  elif [[ $risk_score -ge 40 ]]; then risk_label="MEDIUM";       risk_color="$YELLOW"
  elif [[ $risk_score -ge 20 ]]; then risk_label="LOW";          risk_color="$GREEN"
  else                                 risk_label="MINIMAL";     risk_color="$LGREEN"
  fi

  local bar_filled=$(( risk_score * 50 / 100 ))
  local bar_empty=$(( 50 - bar_filled ))
  local bar="${risk_color}$(printf '█%.0s' $(seq 1 $bar_filled))${RESET}${DIM}$(printf '░%.0s' $(seq 1 $bar_empty))${RESET}"

  echo -e "  ${BOLD}${WHITE}  Risk Score:${RESET}"
  echo ""
  printf "  ${CYAN}  [${RESET}%b${CYAN}]${RESET}  ${risk_color}${BOLD}%d/100  %s${RESET}\n" "$bar" "$risk_score" "$risk_label"
  echo ""

  if [[ ${#risk_factors[@]} -gt 0 ]]; then
    echo -e "  ${BOLD}${WHITE}  Risk Factors:${RESET}"
    for factor in "${risk_factors[@]}"; do
      _entry_hi "  ${factor}"
    done
  fi

  echo ""
  _divider
  echo -e "  ${BOLD}${WHITE}  Recommended Next Steps:${RESET}"
  echo ""
  [[ ${#VULNS[@]} -gt 0 ]]       && _entry_hi  "  Investigate nuclei findings — prioritize CRITICAL and HIGH severity"
  [[ ${#ENDPOINTS[@]} -gt 0 ]]   && _entry_med "  Test HIGH-tagged endpoints for sensitive data exposure"
  [[ ${#PARAMS[@]} -gt 0 ]]      && _entry_med "  Fuzz parameters for SQLi, XSS, LFI, IDOR, Open Redirect"
  [[ ${#EMAILS[@]} -gt 0 ]]      && _entry_low "  Run phishing / password spray simulation (if in scope)"
  [[ ${#SUBDOMAINS[@]} -gt 0 ]]  && _entry_low "  Test subdomains for subdomain takeover (subjack / nuclei templates)"
  [[ ${#OPEN_PORTS[@]} -gt 0 ]]  && _entry_med "  Manually verify exposed services (FTP, RDP, Telnet, Redis, etc.)"
  echo ""

  # ════════════════════════════════════════════════════════════════════════════
  #  CATEGORY 15 — REPORT FILE LOCATIONS
  # ════════════════════════════════════════════════════════════════════════════
  _cat_header 15 "REPORT FILES" "📁"
  echo ""

  printf "  ${CYAN}  %-12s  %s${RESET}\n" "FORMAT" "FILE PATH"
  _divider

  local report_dir="${OUTPUT_DIR}/reports"
  ls -1 "${report_dir}/" 2>&1 | while read -r f; do
    local ext="${f##*.}"
    local ext_col="$WHITE"
    case "$ext" in
      html) ext_col="$LGREEN"   ;;
      json) ext_col="$YELLOW"   ;;
      txt)  ext_col="$CYAN"     ;;
    esac
    printf "  ${GREEN}  ►${RESET}  ${ext_col}%-12s${RESET}  ${WHITE}%s/%s${RESET}\n" \
           "[$ext]" "$report_dir" "$f"
  done || echo -e "  ${GRAY}  No reports generated.${RESET}"

  echo ""
  _divider

  # ── Final footer ───────────────────────────────────────────────────────────
  echo ""
  echo -e "  ${MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "  ${MAGENTA}║${RESET}  ${LRED}⚠  Handle all findings responsibly.${RESET}                                      ${MAGENTA}║${RESET}"
  echo -e "  ${MAGENTA}║${RESET}  ${GRAY}  Unauthorized use of this data is illegal.${RESET}                                ${MAGENTA}║${RESET}"
  echo -e "  ${MAGENTA}║${RESET}  ${CYAN}  CyberRecon V4 v${VERSION} — For Authorized Security Testing Only${RESET}          ${MAGENTA}║${RESET}"
  echo -e "  ${MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""
}

# =============================================================================
#  FINAL SUMMARY
# =============================================================================
final_summary() {
  local end_time=$(date +%s)
  local duration=$(( end_time - START_TIME ))
  local mins=$(( duration / 60 ))
  local secs=$(( duration % 60 ))

  section "FINAL SUMMARY"

  echo -e "  ${BOLD}${WHITE}Target   :${RESET}  ${LCYAN}${TARGET}${RESET}"
  echo -e "  ${BOLD}${WHITE}Type     :${RESET}  ${TARGET_TYPE}"
  echo -e "  ${BOLD}${WHITE}Duration :${RESET}  ${mins}m ${secs}s"
  echo -e "  ${BOLD}${WHITE}Output   :${RESET}  ${CYAN}${OUTPUT_DIR}${RESET}"
  echo ""

  echo -e "  ${LBLUE}Results Summary:${RESET}"
  echo -e "    ${GREEN}▸${RESET}  Subdomains Found  : ${WHITE}${#SUBDOMAINS[@]}${RESET}"
  echo -e "    ${GREEN}▸${RESET}  Live Hosts        : ${WHITE}${#LIVE_HOSTS[@]}${RESET}"
  echo -e "    ${GREEN}▸${RESET}  Emails Found      : ${WHITE}${#EMAILS[@]}${RESET}"
  echo -e "    ${GREEN}▸${RESET}  Open Ports        : ${WHITE}${#OPEN_PORTS[@]}${RESET}"
  echo -e "    ${GREEN}▸${RESET}  Total URLs        : ${WHITE}${#URLS[@]}${RESET}"
  echo -e "    ${GREEN}▸${RESET}  Interesting Eps   : ${WHITE}${#ENDPOINTS[@]}${RESET}"
  echo -e "    ${GREEN}▸${RESET}  Parameters        : ${WHITE}${#PARAMS[@]}${RESET}"
  echo -e "    ${RED}▸${RESET}  Vulnerabilities   : ${WHITE}${#VULNS[@]}${RESET}"
  echo ""

  echo -e "  ${LBLUE}Reports:${RESET}"
  ls -1 "${OUTPUT_DIR}/reports/" 2>&1 | while read -r f; do
    echo -e "    ${CYAN}→${RESET}  ${OUTPUT_DIR}/reports/${f}"
  done
  echo ""
  echo -e "  ${LRED}⚠️  Handle this data responsibly and securely.${RESET}"
  echo -e "  ${GRAY}  CyberRecon V4 — Authorized Testing Only${RESET}"
  echo ""
}

# =============================================================================
#  MAIN ENTRY POINT
# =============================================================================
main() {
  banner
  parse_args "$@"
  normalize_target

  check_tools

  # ── Run phases ─────────────────────────────────────────────────────────────
  if [[ "$ACTIVE_ONLY" == false ]]; then
    phase_subdomain_enum
    phase_osint
    phase_dns
    phase_web_tech
  fi

  if [[ "$PASSIVE_ONLY" == false ]]; then
    phase_active_recon
    phase_attack_surface
    phase_network_scan
    phase_vuln_scan
  fi

  phase_report
  display_terminal_results
  final_summary
}

# ─── TRAP: clean up spinner on Ctrl+C ────────────────────────────────────────
trap 'spinner_stop; echo -e "\n\n  ${YELLOW}[!] Interrupted by user — partial results saved in ${OUTPUT_DIR}${RESET}\n"; exit 130' INT TERM

main "$@"
