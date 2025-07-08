#!/bin/bash

# Advanced Reconnaissance Pipeline
# Author: Security Research Team
# Purpose: Comprehensive automated reconnaissance for authorized security testing
# Usage: ./recon_pipeline.sh <target_domain>

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TARGET="$1"
WORKSPACE="recon_$(date +%Y%m%d_%H%M%S)_${TARGET}"
THREADS=50
WORDLIST_DIR="/usr/share/wordlists"
TOOLS_DIR="$HOME/tools"

# Create workspace
mkdir -p "$WORKSPACE"/{subdomains,ports,web,vulns,screenshots,nuclei,wordlists}
cd "$WORKSPACE"

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a recon.log
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a recon.log
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a recon.log
}

# Banner
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                    ADVANCED RECON PIPELINE                   ║
║                                                               ║
║  ⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️                  ║
║                                                               ║
║  This tool is designed for:                                   ║
║  • Bug bounty programs                                        ║
║  • Authorized penetration testing                            ║
║  • Your own infrastructure assessment                         ║
║                                                               ║
║  Ensure you have proper authorization before use!            ║
╚═══════════════════════════════════════════════════════════════╝
EOF

# Validate target
if [[ ! "$TARGET" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
    error "Invalid domain format: $TARGET"
    exit 1
fi

log "Starting reconnaissance for: $TARGET"
log "Workspace: $PWD"

# Phase 1: Subdomain Enumeration
phase1_subdomains() {
    log "Phase 1: Subdomain Enumeration"
    
    # Subfinder
    log "Running Subfinder..."
    subfinder -d "$TARGET" -silent -o subdomains/subfinder.txt 2>/dev/null || warning "Subfinder failed"
    
    # Amass
    log "Running Amass..."
    timeout 600 amass enum -passive -d "$TARGET" -o subdomains/amass.txt 2>/dev/null || warning "Amass timeout/failed"
    
    # Assetfinder
    log "Running Assetfinder..."
    assetfinder --subs-only "$TARGET" > subdomains/assetfinder.txt 2>/dev/null || warning "Assetfinder failed"
    
    # Certificate Transparency
    log "Checking Certificate Transparency..."
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subdomains/crtsh.txt 2>/dev/null || warning "CT lookup failed"
    
    # DNS Brute Force
    log "DNS Brute Force with common subdomains..."
    if [[ -f "$WORDLIST_DIR/SecLists/Discovery/DNS/subdomains-top1million-5000.txt" ]]; then
        massdns -r /opt/massdns/lists/resolvers.txt -t A -o S -w subdomains/bruteforce.txt -s 1000 \
            <(sed "s/$/.${TARGET}/" "$WORDLIST_DIR/SecLists/Discovery/DNS/subdomains-top1million-5000.txt") 2>/dev/null || warning "MassDNS failed"
        cat subdomains/bruteforce.txt | awk '{print $1}' | sed 's/\.$//g' > subdomains/bruteforce_clean.txt
    fi
    
    # Combine and deduplicate
    cat subdomains/*.txt 2>/dev/null | sort -u | grep -E "\.$TARGET$" > subdomains/all_subdomains.txt
    
    # Resolve subdomains
    log "Resolving subdomains..."
    puredns resolve subdomains/all_subdomains.txt -r /opt/massdns/lists/resolvers.txt --write subdomains/resolved.txt 2>/dev/null || {
        # Fallback to basic resolution
        for sub in $(cat subdomains/all_subdomains.txt); do
            if dig +short "$sub" A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null 2>&1; then
                echo "$sub" >> subdomains/resolved.txt
            fi
        done
    }
    
    # HTTP/HTTPS probe
    log "Probing for HTTP/HTTPS services..."
    httpx -l subdomains/resolved.txt -silent -o subdomains/live.txt -threads "$THREADS" 2>/dev/null || warning "HTTPx failed"
    
    SUBDOMAIN_COUNT=$(wc -l < subdomains/resolved.txt 2>/dev/null || echo "0")
    LIVE_COUNT=$(wc -l < subdomains/live.txt 2>/dev/null || echo "0")
    log "Found $SUBDOMAIN_COUNT subdomains, $LIVE_COUNT are live"
}

# Phase 2: Port Scanning
phase2_ports() {
    log "Phase 2: Port Scanning"
    
    # Extract IPs from resolved subdomains
    for domain in $(cat subdomains/resolved.txt 2>/dev/null || echo ""); do
        dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    done | sort -u > ports/ips.txt
    
    if [[ ! -s ports/ips.txt ]]; then
        warning "No IPs found for port scanning"
        return
    fi
    
    # Nmap scan
    log "Running Nmap scan..."
    nmap -sS -sV -sC -T4 --top-ports 1000 -iL ports/ips.txt -oA ports/nmap_scan 2>/dev/null || warning "Nmap failed"
    
    # Masscan for quick port discovery
    log "Running Masscan..."
    masscan -iL ports/ips.txt -p1-65535 --rate=1000 -oG ports/masscan.txt 2>/dev/null || warning "Masscan failed"
    
    # Parse results
    if [[ -f ports/nmap_scan.gnmap ]]; then
        grep "open" ports/nmap_scan.gnmap | awk '{print $2 ":" $4}' | sed 's/\/open//' > ports/open_ports.txt
    fi
}

# Phase 3: Web Application Discovery
phase3_web() {
    log "Phase 3: Web Application Discovery"
    
    # Directory bruteforcing
    log "Directory bruteforcing with Gobuster..."
    mkdir -p web/gobuster
    while IFS= read -r url; do
        domain=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
        log "Scanning $url"
        gobuster dir -u "$url" -w "$WORDLIST_DIR/dirbuster/directory-list-2.3-medium.txt" \
            -o "web/gobuster/$domain.txt" -t "$THREADS" -q --timeout 10s 2>/dev/null &
    done < <(cat subdomains/live.txt 2>/dev/null || echo "")
    wait
    
    # Technology detection
    log "Technology detection with Wappalyzer..."
    mkdir -p web/tech
    while IFS= read -r url; do
        domain=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
        whatweb "$url" > "web/tech/$domain.txt" 2>/dev/null &
    done < <(cat subdomains/live.txt 2>/dev/null || echo "")
    wait
    
    # Screenshot capture
    log "Capturing screenshots..."
    gowitness file -f subdomains/live.txt -P screenshots/ --threads "$THREADS" 2>/dev/null || warning "Screenshots failed"
}

# Phase 4: Vulnerability Scanning
phase4_vulns() {
    log "Phase 4: Vulnerability Scanning"
    
    # Nuclei scanning
    log "Running Nuclei vulnerability scans..."
    nuclei -l subdomains/live.txt -t ~/nuclei-templates/ -o nuclei/results.txt -c "$THREADS" -silent 2>/dev/null || warning "Nuclei failed"
    
    # SSL/TLS testing
    log "SSL/TLS configuration testing..."
    mkdir -p vulns/ssl
    while IFS= read -r url; do
        domain=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
        if [[ "$url" == https://* ]]; then
            testssl.sh "$domain" > "vulns/ssl/$domain.txt" 2>/dev/null &
        fi
    done < <(cat subdomains/live.txt 2>/dev/null || echo "")
    wait
    
    # Check for common vulnerabilities
    log "Checking for common web vulnerabilities..."
    mkdir -p vulns/common
    while IFS= read -r url; do
        domain=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
        {
            # Check for admin panels
            for path in admin admin.php administrator login wp-admin cpanel; do
                status=$(curl -s -o /dev/null -w "%{http_code}" "$url/$path")
                if [[ "$status" == "200" ]]; then
                    echo "Admin panel found: $url/$path"
                fi
            done
            
            # Check for common files
            for file in robots.txt sitemap.xml .git/config backup.sql; do
                status=$(curl -s -o /dev/null -w "%{http_code}" "$url/$file")
                if [[ "$status" == "200" ]]; then
                    echo "Interesting file: $url/$file"
                fi
            done
        } > "vulns/common/$domain.txt" &
    done < <(cat subdomains/live.txt 2>/dev/null || echo "")
    wait
}

# Phase 5: Reporting
phase5_report() {
    log "Phase 5: Generating Report"
    
    cat << EOF > report.md
# Reconnaissance Report for $TARGET
**Generated:** $(date)
**Workspace:** $PWD

## Summary
- **Subdomains Found:** $(wc -l < subdomains/resolved.txt 2>/dev/null || echo "0")
- **Live Services:** $(wc -l < subdomains/live.txt 2>/dev/null || echo "0")
- **Open Ports:** $(wc -l < ports/open_ports.txt 2>/dev/null || echo "0")
- **Nuclei Findings:** $(wc -l < nuclei/results.txt 2>/dev/null || echo "0")

## Live Subdomains
\`\`\`
$(cat subdomains/live.txt 2>/dev/null || echo "None found")
\`\`\`

## Open Ports
\`\`\`
$(cat ports/open_ports.txt 2>/dev/null || echo "None found")
\`\`\`

## Vulnerability Findings
\`\`\`
$(cat nuclei/results.txt 2>/dev/null | head -20 || echo "None found")
\`\`\`

## Directory Enumeration Results
$(find web/gobuster -name "*.txt" -exec echo "### {}" \; -exec head -10 {} \; 2>/dev/null || echo "No results")

---
*This report was generated by the Advanced Recon Pipeline*
*Ensure you have proper authorization before conducting security testing*
EOF

    log "Report generated: report.md"
}

# Cleanup function
cleanup() {
    log "Cleaning up background processes..."
    jobs -p | xargs -r kill 2>/dev/null || true
}

# Trap cleanup on exit
trap cleanup EXIT

# Main execution
main() {
    # Check for required tools
    required_tools=(subfinder amass assetfinder httpx nmap gobuster nuclei whatweb)
    missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        log "Please install missing tools before running the pipeline"
        exit 1
    fi
    
    # Run phases
    phase1_subdomains
    phase2_ports
    phase3_web
    phase4_vulns
    phase5_report
    
    log "Reconnaissance complete! Check the workspace: $PWD"
    log "Report available at: $PWD/report.md"
}

# Argument validation
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <target_domain>"
    echo "Example: $0 example.com"
    exit 1
fi

# Run main function
main