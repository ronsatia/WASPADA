#!/bin/bash

# =============================================================
# WASPADA - Web Analysis & Security Protocol Assessment
# 🛡️ Alat Audit Keamanan Website (Vulnerability Scanner)
# Script By Ronis
# =============================================================

# -- Definisi Warna --
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# -- Fungsi Banner --
banner() {
    clear
    echo -e "${BLUE}██╗    ██╗ █████╗ ███████╗███████╗ █████╗ ███████╗ █████╗ ${NC}"
    echo -e "${BLUE}██║    ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗${NC}"
    echo -e "${WHITE}██║ █╗ ██║███████║███████╗███████║███████║██║  ██║███████║${NC}"
    echo -e "${WHITE}██║███╗██║██╔══██║╚════██║██╔════╝██╔══██║██║  ██║██╔══██║${NC}"
    echo -e "${BLUE}╚███╔███╔╝██║  ██║███████║██║     ██║  ██║███████║██║  ██║${NC}"
    echo -e "${BLUE} ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝${NC}"
    echo -e "${CYAN}   Web Analysis & Security Protocol Assessment for Digital Assets${NC}"
    echo -e "${YELLOW}               [ Created By Ronis ]                ${NC}"
    echo -e "============================================================"
    echo ""
}

banner

# -- Input Target --
echo -e "${WHITE}Masukkan URL Target (contoh: site.com atau www.site.com):${NC}"
read -p "🎯 Target > " input_url

# Validasi URL
if [[ -z "$input_url" ]]; then
    echo -e "${RED}[!] URL tidak boleh kosong!${NC}"
    exit 1
fi

# Menambahkan protokol jika belum ada
if [[ ! $input_url =~ ^https?:// ]]; then
    target="https://$input_url"
else
    target="$input_url"
fi

echo -e "\n${YELLOW}[*] Memulai Protokol WASPADA pada: $target${NC}"
echo -e "${YELLOW}[*] Mohon tunggu sebentar...${NC}"
sleep 2

# -- MODUL 1: HEADER ANALYSIS --
echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${WHITE}[1] Menganalisis Header Keamanan (Security Headers)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Mengambil header server
headers=$(curl -s -I -L "$target")

# Fungsi Cek Header
check_header() {
    local h_name=$1
    if echo "$headers" | grep -iq "$h_name"; then
        echo -e "   ${GREEN}[AMAN]${NC} $h_name ditemukan."
    else
        echo -e "   ${RED}[RAWAN]${NC} $h_name TIDAK ditemukan!"
    fi
}

check_header "X-Frame-Options"          # Mencegah Clickjacking
check_header "X-XSS-Protection"         # Mencegah Cross Site Scripting
check_header "X-Content-Type-Options"   # Mencegah MIME Sniffing
check_header "Strict-Transport-Security"# Memaksa HTTPS

# -- MODUL 2: FILE SENSITIF SCANNER --
echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${WHITE}[2] Memindai File Sensitif & Terbuka${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Daftar file yang sering bocor
files=(
    "robots.txt"
    "sitemap.xml"
    ".env"
    ".git/config"
    ".htaccess"
    "config.php"
    "wp-config.php.bak"
    "admin/"
    "login/"
    "dashboard/"
)

for file in "${files[@]}"; do
    # Cek status HTTP (ambil code saja)
    status=$(curl -s -o /dev/null -w "%{http_code}" "$target/$file")
    
    if [[ "$status" == "200" ]]; then
        echo -e "   ${RED}[BAHAYA]${NC} Ditemukan: $target/$file (Status: 200 OK)"
    elif [[ "$status" == "403" ]]; then
        echo -e "   ${YELLOW}[TERKUNCI]${NC} Ada tapi dilarang: $file (Status: 403 Forbidden)"
    else
        # Tidak menampilkan yang 404 agar tidak spamming
        : 
    fi
done

# -- MODUL 3: TEKNOLOGI SERVER --
echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${WHITE}[3] Informasi Server & Teknologi${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

server_sig=$(echo "$headers" | grep -i "Server:")
if [[ -n "$server_sig" ]]; then
    echo -e "   ${GREEN}[INFO]${NC} $server_sig"
else
    echo -e "   ${YELLOW}[INFO]${NC} Signature Server disembunyikan."
fi

php_ver=$(echo "$headers" | grep -i "X-Powered-By:")
if [[ -n "$php_ver" ]]; then
    echo -e "   ${RED}[WARN]${NC} Versi PHP Terlihat: $php_ver (Sebaiknya disembunyikan)"
fi

echo -e "\n${CYAN}============================================================${NC}"
echo -e "${WHITE}  Analisis Selesai. Tetap Waspada!${NC}"
echo -e "${YELLOW}  Script By Ronis${NC}"
echo -e "${CYAN}============================================================${NC}"
