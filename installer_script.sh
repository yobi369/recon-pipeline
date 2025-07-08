#!/bin/bash

# Advanced Recon Pipeline - Auto Installer
# This script installs all required tools and dependencies

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "Don't run this script as root!"
        exit 1
    fi
}

check_go() {
    if ! command -v go &> /dev/null; then
        error "Go is not installed. Please install Go first:"
        echo "wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz"
        echo "sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz"
        echo "echo 'export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin' >> ~/.bashrc"
        echo "source ~/.bashrc"
        exit 1
    fi
    log "Go is installed: $(go version)"
}

install_system_packages() {
    log "Installing system packages..."
    
    if command -v apt &> /dev/null; then
        sudo apt update
        sudo apt install -y \
            nmap \
            masscan \
            whatweb \
            jq \
            curl \
            dnsutils \
            git \
            python3 \
            python3-pip \
            libpcap-dev
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap masscan jq curl bind-utils git python3 python3-pip libpcap-devel
    else
        error "Unsupported package manager. Please install packages manually."
        exit 1
    fi
    
    log "System packages installed successfully"
}

install_go_tools() {
    log "Installing Go-based reconnaissance tools..."
    
    # Core tools
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/OJ/gobuster/v3@latest
    go install -v github.com/tomnomnom/assetfinder@latest
    go install -v github.com/d3mondev/puredns/v2@latest
    go install -v github.com/sensepost/gowitness@latest
    
    # Install Amass
    go install -v github.com/owasp-amass/amass/v4/...@master
    
    log "Go tools installed successfully"
}

install_additional_tools() {
    log "Installing additional tools..."
    
    # TestSSL
    if [[ ! -f /usr/local/bin/testssl.sh ]]; then
        sudo wget -O /usr/local/bin/testssl.sh https://testssl.sh/testssl.sh
        sudo chmod +x /usr/local/bin/testssl.sh
    fi
    
    log "Additional tools installed"
}

setup_wordlists() {
    log "Setting up wordlists..."
    
    # Create wordlists directory
    sudo mkdir -p /usr/share/wordlists
    
    # Download SecLists if not exists
    if [[ ! -d /usr/share/wordlists/SecLists ]]; then
        sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
    else
        log "SecLists already exists, updating..."
        sudo git -C /usr/share/wordlists/SecLists pull
    fi
    
    log "Wordlists setup complete"
}

setup_resolvers() {
    log "Setting up DNS resolvers..."
    
    # Create directory
    sudo mkdir -p /opt/massdns/lists
    
    # Download resolvers
    sudo wget -O /opt/massdns/lists/resolvers.txt \
        https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt
    
    log "DNS resolvers setup complete"
}

update_nuclei_templates() {
    log "Updating Nuclei templates..."
    nuclei -update-templates
    log "Nuclei templates updated"
}

verify_installation() {
    log "Verifying installation..."
    
    tools=(subfinder httpx nuclei gobuster assetfinder puredns gowitness amass)
    missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        else
            echo "✓ $tool installed"
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing tools: ${missing_tools[*]}"
        return 1
    fi
    
    log "All tools verified successfully!"
}

create_recon_script() {
    log "Creating recon pipeline script..."
    
    cat > ~/recon_pipeline.sh << 'SCRIPT_EOF'
#!/bin/bash

# Advanced Reconnaissance Pipeline
# Auto-generated installer script

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

TARGET="${1:-}"
WORKSPACE="recon_$(date +%Y%m%d_%H%M%S)_${TARGET}"
THREADS=50
WORDLIST_DIR="/usr/share/wordlists"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target_domain>"
    echo "Example: $0 example.com"
    exit 1
fi

# Validate domain format
if [[ ! "$TARGET" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
    echo -e "${RED}Invalid domain format: $TARGET${NC}"
    exit 1
fi

# Create workspace
mkdir -p "$WORKSPACE"/{subdomains,ports,web,vulns,screenshots,nuclei}
cd "$WORKSPACE"

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1" | tee -a recon.log
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $1" | tee -a recon.log
}

# Banner
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                    ADVANCED RECON PIPELINE                   ║
║                                                               ║
║  ⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️                  ║
╚═══════════════════════════════════════════════════════════════╝
EOF

log "Starting reconnaissance for: $TARGET"
log "Workspace: $PWD"

# Phase 1: Subdomain Enumeration
log "Phase 1: Subdomain Enumeration"

log "Running Subfinder..."
subfinder -d "$TARGET" -silent -o subdomains/subfinder.txt 2>/dev/null || true

log "Running Amass..."
timeout 300 amass enum -passive -d "$TARGET" -o subdomains/amass.txt 2>/dev/null || true

log "Running Assetfinder..."
assetfinder --subs-only "$TARGET" > subdomains/assetfinder.txt 2>/dev/null || true

log "Checking Certificate Transparency..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > subdomains/crtsh.txt || true

# Combine and deduplicate
cat subdomains/*.txt 2>/dev/null | sort -u | grep -E "\.$TARGET$" > subdomains/all_subdomains.txt || true

# Resolve subdomains
log "Resolving subdomains..."
if command -v puredns &> /dev/null && [[ -f /opt/massdns/lists/resolvers.txt ]]; then
    puredns resolve subdomains/all_subdomains.txt -r /opt/massdns/lists/resolvers.txt --write subdomains/resolved.txt 2>/dev/null || {
        # Fallback resolution
        for sub in $(cat subdomains/all_subdomains.txt 2>/dev/null); do
            if dig +short "$sub" A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null 2>&1; then
                echo "$sub" >> subdomains/resolved.txt
            fi
        done
    }
else
    cp subdomains/all_subdomains.txt subdomains/resolved.txt
fi

# HTTP/HTTPS probe
log "Probing for HTTP/HTTPS services..."
httpx -l subdomains/resolved.txt -silent -o subdomains/live.txt -threads "$THREADS" 2>/dev/null || true

SUBDOMAIN_COUNT=$(wc -l < subdomains/resolved.txt 2>/dev/null || echo "0")
LIVE_COUNT=$(wc -l < subdomains/live.txt 2>/dev/null || echo "0")
log "Found $SUBDOMAIN_COUNT subdomains, $LIVE_COUNT are live"

# Phase 2: Directory Enumeration
log "Phase 2: Directory Enumeration"
mkdir -p web/gobuster

if [[ -f subdomains/live.txt ]] && [[ -s subdomains/live.txt ]]; then
    while IFS= read -r url; do
        domain=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
        log "Scanning directories for $url"
        
        if [[ -f "$WORDLIST_DIR/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt" ]]; then
            timeout 300 gobuster dir -u "$url" -w "$WORDLIST_DIR/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt" \
                -o "web/gobuster/$domain.txt" -t 20 -q --timeout 10s 2>/dev/null || true
        fi
    done < subdomains/live.txt
fi

# Phase 3: Technology Detection
log "Phase 3: Technology Detection"
mkdir -p web/tech

if [[ -f subdomains/live.txt ]] && [[ -s subdomains/live.txt ]]; then
    while IFS= read -r url; do
        domain=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
        whatweb "$url" > "web/tech/$domain.txt" 2>/dev/null || true
    done < subdomains/live.txt
fi

# Phase 4: Nuclei Scanning
log "Phase 4: Vulnerability Scanning with Nuclei"
if [[ -f subdomains/live.txt ]] && [[ -s subdomains/live.txt ]]; then
    nuclei -l subdomains/live.txt -t ~/nuclei-templates/ -o nuclei/results.txt -c "$THREADS" -silent 2>/dev/null || true
fi

# Phase 5: Screenshots
log "Phase 5: Taking Screenshots"
if [[ -f subdomains/live.txt ]] && [[ -s subdomains/live.txt ]] && command -v gowitness &> /dev/null; then
    gowitness file -f subdomains/live.txt -P screenshots/ --threads 10 2>/dev/null || true
fi

# Generate Report
log "Generating Report"
cat << EOF > report.md
# Reconnaissance Report for $TARGET
**Generated:** $(date)
**Workspace:** $PWD

## Summary
- **Subdomains Found:** $(wc -l < subdomains/resolved.txt 2>/dev/null || echo "0")
- **Live Services:** $(wc -l < subdomains/live.txt 2>/dev/null || echo "0")
- **Nuclei Findings:** $(wc -l < nuclei/results.txt 2>/dev/null || echo "0")

## Live Subdomains
\`\`\`
$(cat subdomains/live.txt 2>/dev/null | head -20 || echo "None found")
\`\`\`

## Vulnerability Findings
\`\`\`
$(cat nuclei/results.txt 2>/dev/null | head -20 || echo "None found")
\`\`\`

## Directory Enumeration Results
$(find web/gobuster -name "*.txt" -exec echo "### {}" \; -exec head -10 {} \; 2>/dev/null || echo "No results")

---
*Report generated by Advanced Recon Pipeline*
EOF

log "Reconnaissance complete!"
log "Results saved in: $PWD"
log "Report available at: $PWD/report.md"

# Summary
echo
echo -e "${CYAN}=== RECONNAISSANCE SUMMARY ===${NC}"
echo -e "Target: ${YELLOW}$TARGET${NC}"
echo -e "Subdomains: ${GREEN}$(wc -l < subdomains/resolved.txt 2>/dev/null || echo "0")${NC}"
echo -e "Live services: ${GREEN}$(wc -l < subdomains/live.txt 2>/dev/null || echo "0")${NC}"
echo -e "Vulnerabilities: ${RED}$(wc -l < nuclei/results.txt 2>/dev/null || echo "0")${NC}"
echo -e "Workspace: ${BLUE}$PWD${NC}"
echo
SCRIPT_EOF

    chmod +x ~/recon_pipeline.sh
    log "Recon script created at ~/recon_pipeline.sh"
}

main() {
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║            ADVANCED RECON PIPELINE INSTALLER                 ║
║                                                               ║
║  This installer will set up all required tools for           ║
║  automated reconnaissance and vulnerability scanning          ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    check_root
    check_go
    
    log "Starting installation process..."
    
    install_system_packages
    install_go_tools
    install_additional_tools
    setup_wordlists
    setup_resolvers
    update_nuclei_templates
    create_recon_script
    
    if verify_installation; then
        echo
        echo -e "${GREEN}✅ Installation completed successfully!${NC}"
        echo
        echo -e "${YELLOW}Usage:${NC}"
        echo -e "  ${BLUE}~/recon_pipeline.sh example.com${NC}"
        echo
        echo -e "${YELLOW}Example:${NC}"
        echo -e "  ${BLUE}~/recon_pipeline.sh testphp.vulnweb.com${NC}"
        echo
        echo -e "${RED}⚠️  Remember: Only test domains you own or have explicit permission to test!${NC}"
        echo
    else
        error "Installation verification failed!"
        exit 1
    fi
}

main "$@"