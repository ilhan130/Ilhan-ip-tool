#!/data/data/com.termux/files/usr/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Trap Ctrl+C
trap ctrl_c INT

function ctrl_c() {
    echo -e "\n\n${RED}[!] Exiting...${NC}"
    exit 0
}

function print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║          ILHAN IP TOOL V1           ║"
    echo "║               insta ilhan.pk                ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

function print_header() {
    echo -e "\n${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}$1${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
}

function get_self_ip_info() {
    print_header "SELF IP INFORMATION"
    
    # Get public IP
    echo -e "${GREEN}[+]${NC} Fetching your public IP address..."
    PUBLIC_IP=$(curl -s -m 10 https://api.ipify.org)
    
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(curl -s -m 10 https://ipinfo.io/ip)
    fi
    
    echo -e "${GREEN}[+]${NC} Your Public IP: ${BOLD}$PUBLIC_IP${NC}"
    
    # Get local IP information
    echo -e "\n${CYAN}[*]${NC} Local Network Information:"
    
    # Method 1: Using ip command
    echo -e "${GREEN}[+]${NC} Network Interfaces:"
    ip -4 addr show | grep -E "^[0-9]+:|inet " | grep -v "127.0.0.1" | while read line; do
        if [[ $line == *":"* ]]; then
            echo -e "  ${YELLOW}Interface:${NC} $(echo $line | cut -d: -f2)"
        else
            echo -e "    ${GREEN}IP:${NC} $(echo $line | awk '{print $2}')"
        fi
    done
    
    # Get gateway
    echo -e "\n${GREEN}[+]${NC} Gateway/Router:"
    ip route | grep default | awk '{print $3}' | head -1
    
    # Get DNS servers
    echo -e "\n${GREEN}[+]${NC} DNS Servers:"
    cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}' || echo "Not available"
    
    # Get MAC address
    echo -e "\n${GREEN}[+]${NC} MAC Address:"
    ip link show | grep link/ether | head -1 | awk '{print $2}'
    
    # Check VPN connection
    echo -e "\n${GREEN}[+]${NC} VPN Detection:"
    if ip tuntap show 2>/dev/null | grep -q tun; then
        echo -e "  ${RED}VPN Active${NC} (tun/tap interface detected)"
    else
        echo -e "  ${GREEN}No VPN detected${NC}"
    fi
}

function get_ip_info() {
    local IP=$1
    
    if [ -z "$IP" ]; then
        echo -e "${RED}[!] No IP address provided${NC}"
        return 1
    fi
    
    # Validate IP format
    if ! [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}[!] Invalid IP address format${NC}"
        return 1
    fi
    
    print_header "INFORMATION FOR IP: $IP"
    
    # 1. Basic IP Information
    print_header "1. BASIC IP INFORMATION"
    echo -e "${GREEN}[+]${NC} IP Address: ${BOLD}$IP${NC}"
    
    # 2. IP Type (Public/Private)
    echo -e "\n${GREEN}[+]${NC} IP Type:"
    if [[ $IP =~ ^10\. ]] || [[ $IP =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ $IP =~ ^192\.168\. ]] || [[ $IP == "127.0.0.1" ]]; then
        echo -e "  ${RED}Private IP Address${NC}"
    else
        echo -e "  ${GREEN}Public IP Address${NC}"
    fi
    
    # 3. WHOIS Information
    print_header "2. WHOIS INFORMATION"
    echo -e "${GREEN}[+]${NC} Fetching WHOIS data..."
    whois $IP 2>/dev/null | grep -E "(inetnum:|netname:|country:|descr:|organization:|created:|last-modified:)" | head -10 | while read line; do
        echo -e "  ${CYAN}$line${NC}"
    done
    
    # 4. GeoLocation Information
    print_header "3. GEOLOCATION INFORMATION"
    echo -e "${GREEN}[+]${NC} Fetching geolocation data..."
    GEO_DATA=$(curl -s -m 10 "http://ip-api.com/json/$IP")
    
    if [ ! -z "$GEO_DATA" ] && [ "$GEO_DATA" != "null" ]; then
        echo -e "  ${YELLOW}Country:${NC} $(echo $GEO_DATA | jq -r '.country // "N/A"')"
        echo -e "  ${YELLOW}Country Code:${NC} $(echo $GEO_DATA | jq -r '.countryCode // "N/A"')"
        echo -e "  ${YELLOW}Region:${NC} $(echo $GEO_DATA | jq -r '.regionName // "N/A"')"
        echo -e "  ${YELLOW}City:${NC} $(echo $GEO_DATA | jq -r '.city // "N/A"')"
        echo -e "  ${YELLOW}ZIP Code:${NC} $(echo $GEO_DATA | jq -r '.zip // "N/A"')"
        echo -e "  ${YELLOW}Latitude:${NC} $(echo $GEO_DATA | jq -r '.lat // "N/A"')"
        echo -e "  ${YELLOW}Longitude:${NC} $(echo $GEO_DATA | jq -r '.lon // "N/A"')"
        echo -e "  ${YELLOW}Timezone:${NC} $(echo $GEO_DATA | jq -r '.timezone // "N/A"')"
        echo -e "  ${YELLOW}ISP:${NC} $(echo $GEO_DATA | jq -r '.isp // "N/A"')"
        echo -e "  ${YELLOW}Organization:${NC} $(echo $GEO_DATA | jq -r '.org // "N/A"')"
        echo -e "  ${YELLOW}AS:${NC} $(echo $GEO_DATA | jq -r '.as // "N/A"')"
    else
        echo -e "  ${RED}Geolocation data unavailable${NC}"
    fi
    
    # 5. Reverse DNS
    print_header "4. DNS INFORMATION"
    echo -e "${GREEN}[+]${NC} Reverse DNS Lookup:"
    dig +short -x $IP 2>/dev/null || echo "  Not available"
    
    # 6. Check if IP is responsive
    print_header "5. NETWORK RESPONSIVENESS"
    echo -e "${GREEN}[+]${NC} Ping Test (3 packets):"
    ping -c 3 -W 2 $IP 2>/dev/null | tail -2 || echo "  Host not reachable"
    
    # 7. Check open ports (common ports)
    print_header "6. COMMON PORTS SCAN"
    echo -e "${GREEN}[+]${NC} Checking common ports (quick scan)..."
    PORTS="80 443 22 21 25 53 110 143 3306 3389 8080 8443"
    for PORT in $PORTS; do
        timeout 1 bash -c "echo >/dev/tcp/$IP/$PORT" 2>/dev/null && \
        echo -e "  ${GREEN}Port $PORT${NC}: Open" || \
        echo -e "  ${RED}Port $PORT${NC}: Closed"
    done
    
    # 8. Traceroute information
    print_header "7. NETWORK PATH"
    echo -e "${GREEN}[+]${NC} Traceroute (first 5 hops):"
    traceroute -m 5 -w 1 $IP 2>/dev/null | head -10 || \
    echo "  Traceroute not available (install traceroute package)"
    
    # 9. Check if IP is in blacklists
    print_header "8. SECURITY CHECK"
    echo -e "${GREEN}[+]${NC} Checking common blacklists..."
    
    # List of RBLs to check
    RBL_SERVERS="zen.spamhaus.org bl.spamcop.org b.barracudacentral.org"
    
    # Reverse IP for RBL check
    REV_IP=$(echo $IP | awk -F. '{print $4"."$3"."$2"."$1}')
    
    for RBL in $RBL_SERVERS; do
        RESULT=$(dig +short $REV_IP.$RBL 2>/dev/null)
        if [ ! -z "$RESULT" ]; then
            echo -e "  ${RED}Listed in $RBL${NC}"
        else
            echo -e "  ${GREEN}Not in $RBL${NC}"
        fi
    done
    
    # 10. IP Range Information
    print_header "9. IP RANGE INFORMATION"
    echo -e "${GREEN}[+]${NC} Calculating IP class and range..."
    
    # Determine IP class
    FIRST_OCTET=$(echo $IP | cut -d. -f1)
    if [ $FIRST_OCTET -le 126 ]; then
        CLASS="A"
        echo -e "  ${YELLOW}Class:${NC} $CLASS (Large Networks)"
    elif [ $FIRST_OCTET -le 191 ]; then
        CLASS="B"
        echo -e "  ${YELLOW}Class:${NC} $CLASS (Medium Networks)"
    elif [ $FIRST_OCTET -le 223 ]; then
        CLASS="C"
        echo -e "  ${YELLOW}Class:${NC} $CLASS (Small Networks)"
    elif [ $FIRST_OCTET -le 239 ]; then
        CLASS="D (Multicast)"
    else
        CLASS="E (Reserved)"
    fi
    
    echo -e "  ${YELLOW}Binary:${NC} $(echo $IP | awk -F. '{printf "%08d.%08d.%08d.%08d\n", 
        and($1,255), and($2,255), and($3,255), and($4,255)}' | sed 's/0/0/g; s/1/1/g')"
    
    # 11. Calculate Broadcast Address
    print_header "10. NETWORK CALCULATIONS"
    echo -e "${GREEN}[+]${NC} Network Calculations:"
    
    # For demonstration, assuming /24 subnet for private IPs
    if [[ $IP =~ ^192\.168\. ]]; then
        NETWORK="${IP%.*}.0"
        BROADCAST="${IP%.*}.255"
        echo -e "  ${YELLOW}Network Address:${NC} $NETWORK"
        echo -e "  ${YELLOW}Broadcast Address:${NC} $BROADCAST"
        echo -e "  ${YELLOW}Usable Hosts:${NC} 254"
    fi
    
    # 12. HTTP Headers (if web server)
    print_header "11. HTTP INFORMATION"
    echo -e "${GREEN}[+]${NC} Checking HTTP headers..."
    curl -I -m 5 "http://$IP" 2>/dev/null | head -10 || \
    echo "  No HTTP server detected or timeout"
    
    # 13. SSL Certificate (if HTTPS)
    print_header "12. SSL/TLS INFORMATION"
    echo -e "${GREEN}[+]${NC} Checking SSL certificate..."
    timeout 5 openssl s_client -connect $IP:443 -servername $IP 2>/dev/null | \
    openssl x509 -noout -dates 2>/dev/null | head -2 || \
    echo "  No SSL certificate detected"
    
    # 14. Timezone information
    print_header "13. TIME INFORMATION"
    echo -e "${GREEN}[+]${NC} Current time at IP location:"
    TIMEZONE=$(echo $GEO_DATA | jq -r '.timezone // "UTC"')
    date -d "TZ=\"$TIMEZONE\"" 2>/dev/null || echo "  Timezone: $TIMEZONE"
    
    # 15. Mobile/Carrier detection (if applicable)
    print_header "14. CARRIER INFORMATION"
    echo -e "${GREEN}[+]${NC} ISP Details:"
    if [ ! -z "$GEO_DATA" ]; then
        ISP=$(echo $GEO_DATA | jq -r '.isp // "N/A"')
        ORG=$(echo $GEO_DATA | jq -r '.org // "N/A"')
        AS=$(echo $GEO_DATA | jq -r '.as // "N/A"')
        
        echo -e "  ${YELLOW}ISP:${NC} $ISP"
        echo -e "  ${YELLOW}Organization:${NC} $ORG"
        echo -e "  ${YELLOW}AS Number:${NC} $AS"
        
        # Check for mobile carriers
        MOBILE_KEYWORDS="mobile|cellular|wireless|vodafone|verizon|att|t-mobile|sprint"
        if echo "$ISP$ORG" | grep -qiE "$MOBILE_KEYWORDS"; then
            echo -e "  ${CYAN}⚠  Likely Mobile/Cellular IP${NC}"
        fi
    fi
    
    # 16. Threat Intelligence
    print_header "15. THREAT INTELLIGENCE"
    echo -e "${GREEN}[+]${NC} Checking threat databases..."
    
    # Check against AbuseIPDB (API required for full)
    echo -e "  ${YELLOW}AbuseIPDB Check:${NC} Visit https://www.abuseipdb.com/check/$IP"
    
    # Check against VirusTotal
    echo -e "  ${YELLOW}VirusTotal Check:${NC} Visit https://www.virustotal.com/gui/ip-address/$IP"
    
    # 17. Hosting Provider Info
    print_header "16. HOSTING PROVIDER"
    if [ ! -z "$GEO_DATA" ]; then
        ORG=$(echo $GEO_DATA | jq -r '.org // "N/A"')
        echo -e "  ${YELLOW}Hosting Provider:${NC} $ORG"
        
        # Check for known hosting providers
        HOSTING_PROVIDERS="amazon|google|microsoft|digitalocean|linode|vultr|ovh|hetzner"
        if echo "$ORG" | grep -qiE "$HOSTING_PROVIDERS"; then
            echo -e "  ${CYAN}⚠  Known Cloud/Hosting Provider${NC}"
        fi
    fi
    
    # 18. IP Reputation Score
    print_header "17. REPUTATION SCORE"
    echo -e "${GREEN}[+]${NC} Estimated Reputation:"
    
    # Simple reputation logic based on various factors
    REPUTATION=50  # Start with neutral score
    
    # Adjust based on IP type
    if [[ $IP =~ ^10\. ]] || [[ $IP =~ ^192\.168\. ]] || [[ $IP == "127.0.0.1" ]]; then
        REPUTATION=100  # Private IPs are safe
        echo -e "  ${GREEN}✓ Private IP: Safe${NC}"
    else
        # Check for suspicious ports
        SUSPICIOUS_PORTS="23 445 135 139 3389"
        for PORT in $SUSPICIOUS_PORTS; do
            timeout 1 bash -c "echo >/dev/tcp/$IP/$PORT" 2>/dev/null && \
            REPUTATION=$((REPUTATION - 10))
        done
        
        # Display score
        if [ $REPUTATION -ge 80 ]; then
            echo -e "  ${GREEN}✓ Good Reputation ($REPUTATION/100)${NC}"
        elif [ $REPUTATION -ge 60 ]; then
            echo -e "  ${YELLOW}⚠  Moderate Reputation ($REPUTATION/100)${NC}"
        else
            echo -e "  ${RED}✗ Poor Reputation ($REPUTATION/100)${NC}"
        fi
    fi
    
    # 19. Historical Data
    print_header "18. HISTORICAL DATA"
    echo -e "${GREEN}[+]${NC} Historical Information Sources:"
    echo -e "  ${YELLOW}View Historical Data:${NC}"
    echo -e "    • https://viewdns.info/iphistory/?domain=$IP"
    echo -e "    • https://securitytrails.com/domain/$IP"
    
    # 20. Associated Domains
    print_header "19. ASSOCIATED DOMAINS"
    echo -e "${GREEN}[+]${NC} Reverse IP Lookup for Domains:"
    echo -e "  ${YELLOW}Check:${NC} https://viewdns.info/reverseip/?host=$IP"
    echo -e "  ${YELLOW}Check:${NC} https://rapiddns.io/sameip/$IP"
    
    # 21. Additional Tools
    print_header "20. ADDITIONAL TOOLS & LINKS"
    echo -e "${GREEN}[+]${NC} Useful External Tools:"
    echo -e "  ${CYAN}1.${NC} Shodan: https://www.shodan.io/host/$IP"
    echo -e "  ${CYAN}2.${NC} Censys: https://search.censys.io/hosts/$IP"
    echo -e "  ${CYAN}3.${NC} GreyNoise: https://viz.greynoise.io/ip/$IP"
    echo -e "  ${CYAN}4.${NC} ThreatFox: https://threatfox.abuse.ch/browse.php?search=$IP"
    
    # 22. Network Neighbors
    print_header "21. NETWORK NEIGHBORS"
    echo -e "${GREEN}[+]${NC} Finding IPs in same /24 network:"
    
    if [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\. ]]; then
        NETWORK_PREFIX=$(echo $IP | cut -d. -f1-3)
        echo -e "  ${YELLOW}Network:${NC} $NETWORK_PREFIX.0/24"
        echo -e "  ${YELLOW}IP Range:${NC} $NETWORK_PREFIX.1 - $NETWORK_PREFIX.254"
        echo -e "  ${YELLOW}Total IPs:${NC} 254"
    fi
    
    # 23. Quick Summary
    print_header "22. QUICK SUMMARY"
    echo -e "${GREEN}[+]${NC} Summary for $IP:"
    
    COUNTRY=$(echo $GEO_DATA | jq -r '.country // "Unknown"')
    CITY=$(echo $GEO_DATA | jq -r '.city // "Unknown"')
    ISP=$(echo $GEO_DATA | jq -r '.isp // "Unknown"')
    
    echo -e "  ${YELLOW}Location:${NC} $CITY, $COUNTRY"
    echo -e "  ${YELLOW}Provider:${NC} $ISP"
    echo -e "  ${YELLOW}Type:${NC} $CLASS"
    
    if [[ $IP =~ ^10\. ]] || [[ $IP =~ ^192\.168\. ]]; then
        echo -e "  ${YELLOW}Status:${NC} ${GREEN}Private Network IP${NC}"
    else
        echo -e "  ${YELLOW}Status:${NC} ${CYAN}Public Internet IP${NC}"
    fi
    
    print_header "SCAN COMPLETE"
    echo -e "${GREEN}[✓]${NC} Information gathering completed for ${BOLD}$IP${NC}"
    echo -e "${YELLOW}[!]${NC} Press Ctrl+C to exit"
}

function main_menu() {
    while true; do
        print_banner
        
        echo -e "${WHITE}Select an option:${NC}"
        echo -e "${CYAN}[1]${NC} Get information about your own IP"
        echo -e "${CYAN}[2]${NC} Enter IP address to analyze"
        echo -e "${CYAN}[3]${NC} Quick self IP info (sl command)"
        echo -e "${CYAN}[4]${NC} Batch IP analysis from file"
        echo -e "${CYAN}[5]${NC} Install missing dependencies"
        echo -e "${RED}[0]${NC} Exit"
        echo -e "\n${YELLOW}══════════════════════════════════════════════════${NC}"
        
        read -p "Choose option [0-5]: " choice
        
        case $choice in
            1)
                get_self_ip_info
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "\n${GREEN}[+]${NC} Enter IP address (e.g., 8.8.8.8): "
                read -p "IP: " TARGET_IP
                if [ ! -z "$TARGET_IP" ]; then
                    get_ip_info "$TARGET_IP"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                # Quick self info (sl command functionality)
                get_self_ip_info
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "\n${GREEN}[+]${NC} Enter filename containing IPs (one per line): "
                read -p "Filename: " IP_FILE
                if [ -f "$IP_FILE" ]; then
                    while read LINE_IP; do
                        if [ ! -z "$LINE_IP" ]; then
                            get_ip_info "$LINE_IP"
                            echo -e "\n${YELLOW}──────────────────────────────────────────────────────${NC}\n"
                        fi
                    done < "$IP_FILE"
                else
                    echo -e "${RED}[!] File not found: $IP_FILE${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                install_dependencies
                ;;
            0)
                echo -e "\n${GREEN}[+]${NC} Thank you for using IP Finder!"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

function install_dependencies() {
    print_header "INSTALLING DEPENDENCIES"
    
    echo -e "${GREEN}[+]${NC} Updating packages..."
    pkg update -y
    
    echo -e "${GREEN}[+]${NC} Installing required packages..."
    pkg install -y curl jq whois net-tools dnsutils iproute2 python
    
    echo -e "${GREEN}[+]${NC} Installing Python packages..."
    pip install requests
    
    echo -e "${GREEN}[+]${NC} Installing additional tools..."
    pkg install -y nmap traceroute 2>/dev/null || echo "Some packages not available"
    
    echo -e "\n${GREEN}[✓]${NC} Installation complete!"
    sleep 2
}

# Create alias command 'sl' for quick self info
function create_alias() {
    echo -e "${GREEN}[+]${NC} Creating alias 'sl' for quick self IP info..."
    
    # Check if alias already exists
    if ! grep -q "alias sl=" ~/.bashrc 2>/dev/null; then
        echo "alias sl='bash ~/ipfinder.sh --self'" >> ~/.bashrc
        echo -e "${GREEN}[✓]${NC} Alias 'sl' created. Run 'source ~/.bashrc' to activate."
    else
        echo -e "${YELLOW}[!]${NC} Alias 'sl' already exists."
    fi
}

# Check command line arguments
if [ "$1" == "--self" ] || [ "$1" == "sl" ]; then
    get_self_ip_info
    exit 0
elif [ ! -z "$1" ]; then
    get_ip_info "$1"
    exit 0
fi

# Make script executable
chmod +x ipfinder.sh

# Run main menu
main_menu
