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

# Default PHP server settings
PHP_PORT="8080"
PHP_HOST="localhost"
PHP_URL_PATH="getip"

# Trap Ctrl+C
trap ctrl_c INT

function ctrl_c() {
    echo -e "\n\n${RED}[!] Exiting...${NC}"
    kill_php_server
    exit 0
}

function kill_php_server() {
    if [ ! -z "$PHP_PID" ]; then
        echo -e "${YELLOW}[!]${NC} Stopping PHP server (PID: $PHP_PID)..."
        kill $PHP_PID 2>/dev/null
        PHP_PID=""
    fi
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

function create_php_ip_server() {
    print_header "CREATE PHP IP FINDER SERVER"
    
    # Ask for custom settings
    echo -e "${CYAN}[*]${NC} Customize PHP Server Settings (Press Enter for defaults):"
    
    read -p "Enter port number [default: 8080]: " custom_port
    if [ ! -z "$custom_port" ]; then
        PHP_PORT="$custom_port"
    fi
    
    read -p "Enter URL path [default: getip]: " custom_path
    if [ ! -z "$custom_path" ]; then
        PHP_URL_PATH="$custom_path"
    fi
    
    # Create PHP file
    PHP_FILE="ip_finder.php"
    
    echo -e "\n${GREEN}[+]${NC} Creating PHP file: $PHP_FILE"
    
    cat > "$PHP_FILE" << 'EOF'
<?php
// IP Finder PHP Server
// Created by ILHAN IP TOOL

// Function to get client IP address
function getClientIP() {
    $ip_keys = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    ];
    
    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    return $ip;
                }
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

// Get all visitor information
function getVisitorInfo() {
    $info = [];
    
    // IP Address
    $info['ip_address'] = getClientIP();
    
    // Headers
    $info['headers'] = [];
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $header_name = str_replace('_', ' ', substr($key, 5));
            $header_name = ucwords(strtolower($header_name));
            $header_name = str_replace(' ', '-', $header_name);
            $info['headers'][$header_name] = $value;
        }
    }
    
    // User Agent
    $info['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    // Request Method
    $info['method'] = $_SERVER['REQUEST_METHOD'] ?? 'Unknown';
    
    // Request URI
    $info['request_uri'] = $_SERVER['REQUEST_URI'] ?? 'Unknown';
    
    // Query String
    $info['query_string'] = $_SERVER['QUERY_STRING'] ?? '';
    
    // Timestamp
    $info['timestamp'] = date('Y-m-d H:i:s');
    
    // Server Info
    $info['server_software'] = $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown';
    $info['server_addr'] = $_SERVER['SERVER_ADDR'] ?? 'Unknown';
    $info['server_port'] = $_SERVER['SERVER_PORT'] ?? 'Unknown';
    
    // Geolocation (using IP-API)
    if ($info['ip_address'] != 'Unknown' && $info['ip_address'] != '127.0.0.1') {
        $geo_url = "http://ip-api.com/json/{$info['ip_address']}";
        $geo_data = @file_get_contents($geo_url);
        if ($geo_data) {
            $info['geolocation'] = json_decode($geo_data, true);
        }
    }
    
    return $info;
}

// Handle requests
$request_path = $_SERVER['REQUEST_URI'] ?? '/';

// Main page
if ($request_path == '/' || $request_path == '/getip' || stripos($request_path, '/getip') === 0) {
    $visitor_info = getVisitorInfo();
    
    // Check if JSON output is requested
    if (isset($_GET['format']) && $_GET['format'] == 'json') {
        header('Content-Type: application/json');
        echo json_encode($visitor_info, JSON_PRETTY_PRINT);
        exit;
    }
    
    // HTML Output
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IP Finder - ILHAN Tool</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }
            
            .container {
                background: rgba(255, 255, 255, 0.95);
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                max-width: 800px;
                width: 100%;
                overflow: hidden;
            }
            
            .header {
                background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }
            
            .header h1 {
                font-size: 2.5em;
                margin-bottom: 10px;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.2);
            }
            
            .header .subtitle {
                font-size: 1.2em;
                opacity: 0.9;
            }
            
            .content {
                padding: 40px;
            }
            
            .info-box {
                background: #f8f9fa;
                border-radius: 10px;
                padding: 25px;
                margin-bottom: 25px;
                border-left: 4px solid #4facfe;
            }
            
            .info-box h2 {
                color: #333;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .info-box h2 i {
                color: #4facfe;
            }
            
            .info-item {
                margin-bottom: 10px;
                padding: 8px 0;
                border-bottom: 1px solid #eee;
            }
            
            .info-label {
                font-weight: 600;
                color: #555;
                display: inline-block;
                width: 150px;
            }
            
            .info-value {
                color: #333;
                font-family: 'Courier New', monospace;
                background: #e9ecef;
                padding: 4px 8px;
                border-radius: 4px;
                word-break: break-all;
            }
            
            .ip-display {
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                color: white;
                padding: 25px;
                border-radius: 10px;
                text-align: center;
                margin-bottom: 30px;
            }
            
            .ip-display .label {
                font-size: 1.1em;
                opacity: 0.9;
                margin-bottom: 10px;
            }
            
            .ip-display .ip {
                font-size: 2.5em;
                font-weight: bold;
                font-family: 'Courier New', monospace;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.2);
            }
            
            .buttons {
                display: flex;
                gap: 15px;
                flex-wrap: wrap;
                margin-top: 30px;
            }
            
            .btn {
                padding: 12px 25px;
                border: none;
                border-radius: 50px;
                font-size: 1em;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                text-decoration: none;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
            }
            
            .btn-primary {
                background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                color: white;
            }
            
            .btn-secondary {
                background: #6c757d;
                color: white;
            }
            
            .btn-success {
                background: #28a745;
                color: white;
            }
            
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            }
            
            .footer {
                text-align: center;
                padding: 20px;
                color: #666;
                border-top: 1px solid #eee;
                font-size: 0.9em;
            }
            
            @media (max-width: 600px) {
                .content {
                    padding: 20px;
                }
                
                .header h1 {
                    font-size: 1.8em;
                }
                
                .ip-display .ip {
                    font-size: 1.8em;
                }
                
                .info-label {
                    width: 100%;
                    display: block;
                    margin-bottom: 5px;
                }
            }
        </style>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1><i class="fas fa-search-location"></i> IP Finder</h1>
                <div class="subtitle">by ILHAN IP TOOL</div>
            </div>
            
            <div class="content">
                <div class="ip-display">
                    <div class="label">Your IP Address is:</div>
                    <div class="ip"><?php echo htmlspecialchars($visitor_info['ip_address']); ?></div>
                </div>
                
                <div class="info-box">
                    <h2><i class="fas fa-info-circle"></i> Visitor Information</h2>
                    <div class="info-item">
                        <span class="info-label">IP Address:</span>
                        <span class="info-value"><?php echo htmlspecialchars($visitor_info['ip_address']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">User Agent:</span>
                        <span class="info-value"><?php echo htmlspecialchars($visitor_info['user_agent']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Timestamp:</span>
                        <span class="info-value"><?php echo htmlspecialchars($visitor_info['timestamp']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Request Method:</span>
                        <span class="info-value"><?php echo htmlspecialchars($visitor_info['method']); ?></span>
                    </div>
                </div>
                
                <?php if (isset($visitor_info['geolocation'])): ?>
                <div class="info-box">
                    <h2><i class="fas fa-globe-americas"></i> Geolocation Information</h2>
                    <?php 
                    $geo = $visitor_info['geolocation'];
                    if ($geo['status'] == 'success'):
                    ?>
                    <div class="info-item">
                        <span class="info-label">Country:</span>
                        <span class="info-value"><?php echo htmlspecialchars($geo['country'] ?? 'Unknown'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Region:</span>
                        <span class="info-value"><?php echo htmlspecialchars($geo['regionName'] ?? 'Unknown'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">City:</span>
                        <span class="info-value"><?php echo htmlspecialchars($geo['city'] ?? 'Unknown'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">ISP:</span>
                        <span class="info-value"><?php echo htmlspecialchars($geo['isp'] ?? 'Unknown'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Organization:</span>
                        <span class="info-value"><?php echo htmlspecialchars($geo['org'] ?? 'Unknown'); ?></span>
                    </div>
                    <?php else: ?>
                    <div class="info-item">
                        <span class="info-label">Geolocation:</span>
                        <span class="info-value">Failed to retrieve geolocation data</span>
                    </div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
                
                <div class="info-box">
                    <h2><i class="fas fa-server"></i> Server Information</h2>
                    <div class="info-item">
                        <span class="info-label">Server Address:</span>
                        <span class="info-value"><?php echo htmlspecialchars($visitor_info['server_addr']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Server Port:</span>
                        <span class="info-value"><?php echo htmlspecialchars($visitor_info['server_port']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Server Software:</span>
                        <span class="info-value"><?php echo htmlspecialchars($visitor_info['server_software']); ?></span>
                    </div>
                </div>
                
                <div class="buttons">
                    <a href="?format=json" class="btn btn-primary">
                        <i class="fas fa-code"></i> JSON Output
                    </a>
                    <a href="/" class="btn btn-secondary">
                        <i class="fas fa-sync-alt"></i> Refresh
                    </a>
                    <button onclick="copyIP()" class="btn btn-success">
                        <i class="fas fa-copy"></i> Copy IP
                    </button>
                </div>
            </div>
            
            <div class="footer">
                <p>Powered by ILHAN IP TOOL | PHP Server | <?php echo date('Y'); ?></p>
                <p>Share this link with others to see their IP address</p>
            </div>
        </div>
        
        <script>
            function copyIP() {
                const ip = "<?php echo $visitor_info['ip_address']; ?>";
                navigator.clipboard.writeText(ip).then(() => {
                    alert('IP address copied to clipboard: ' + ip);
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                });
            }
            
            // Auto-refresh every 30 seconds
            setTimeout(() => {
                location.reload();
            }, 30000);
        </script>
    </body>
    </html>
    <?php
    exit;
}

// API endpoint for raw IP
if ($request_path == '/api/ip' || $request_path == '/raw') {
    header('Content-Type: text/plain');
    echo getClientIP();
    exit;
}

// JSON API endpoint
if ($request_path == '/api/json') {
    header('Content-Type: application/json');
    echo json_encode(getVisitorInfo(), JSON_PRETTY_PRINT);
    exit;
}

// Default 404
http_response_code(404);
echo "404 - Page Not Found. Available endpoints: /getip, /api/ip, /api/json";
EOF

    echo -e "${GREEN}[✓]${NC} PHP file created successfully"
    
    # Check if PHP is available
    if ! command -v php &> /dev/null; then
        echo -e "${YELLOW}[!]${NC} PHP is not installed. Installing..."
        pkg install -y php
    fi
    
    # Kill any existing PHP server
    kill_php_server
    
    # Start PHP server
    echo -e "\n${GREEN}[+]${NC} Starting PHP server on port $PHP_PORT..."
    echo -e "${CYAN}[*]${NC} PHP Server URL: http://$PHP_HOST:$PHP_PORT/$PHP_URL_PATH"
    
    php -S "$PHP_HOST:$PHP_PORT" "$PHP_FILE" > /dev/null 2>&1 &
    PHP_PID=$!
    
    echo -e "${GREEN}[✓]${NC} PHP server started with PID: $PHP_PID"
    
    # Get network IP for external access
    NETWORK_IP=$(ip route get 1 | awk '{print $7}' | head -1)
    echo -e "\n${YELLOW}[!]${NC} Access URLs:"
    echo -e "  ${CYAN}Local:${NC}    http://localhost:$PHP_PORT/$PHP_URL_PATH"
    echo -e "  ${CYAN}Network:${NC}  http://$NETWORK_IP:$PHP_PORT/$PHP_URL_PATH"
    
    # Get public IP if available
    echo -e "\n${YELLOW}[!]${NC} If you have port forwarding:"
    echo -e "  ${CYAN}Public:${NC}   http://YOUR-PUBLIC-IP:$PHP_PORT/$PHP_URL_PATH"
    
    # Generate QR code for easy access
    echo -e "\n${GREEN}[+]${NC} Generating access QR code..."
    echo -e "\n${CYAN}┌────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│   Scan QR code to access IP Finder:      │${NC}"
    echo -e "${CYAN}└────────────────────────────────────────────┘${NC}"
    
    # Create simple ASCII QR
    QR_URL="http://$NETWORK_IP:$PHP_PORT/$PHP_URL_PATH"
    echo -e "${WHITE}"
    python3 -c "
import qrcode
import sys
try:
    qr = qrcode.QRCode(version=1, box_size=2, border=1)
    qr.add_data('$QR_URL')
    qr.make(fit=True)
    qr.print_ascii(invert=True)
except:
    print('QR code generation failed. Install: pip install qrcode')
    print('Access URL: $QR_URL')
" 2>/dev/null || echo -e "${YELLOW}Install: pkg install python && pip install qrcode${NC}"
    
    echo -e "${NC}\n${YELLOW}[!]${NC} PHP server is running in background"
    echo -e "${YELLOW}[!]${NC} Press Ctrl+C in this terminal to stop the server"
    
    # Wait for user input
    echo -e "\n${GREEN}[+]${NC} Server logs (Ctrl+C to stop):"
    wait $PHP_PID
}

function get_ip_info() {
    # ... (keep the existing get_ip_info function unchanged) ...
    # [Previous get_ip_info function code remains the same]
    # ... (truncated for brevity, but keep all original content) ...
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
        echo -e "${MAGENTA}[6]${NC} Create PHP IP Finder Server"
        echo -e "${RED}[0]${NC} Exit"
        echo -e "\n${YELLOW}══════════════════════════════════════════════════${NC}"
        
        read -p "Choose option [0-6]: " choice
        
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
            6)
                create_php_ip_server
                read -p "Press Enter to continue..."
                ;;
            0)
                kill_php_server
                echo -e "\n${GREEN}[+]${NC} Thank you for using ILHAN IP TOOL!"
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
    pkg install -y curl jq whois net-tools dnsutils iproute2 php
    
    echo -e "${GREEN}[+]${NC} Installing Python packages for QR code..."
    pip install qrcode[pil] 2>/dev/null || pip install qrcode
    
    echo -e "\n${GREEN}[✓]${NC} Installation complete!"
    sleep 2
}

function create_alias() {
    echo -e "${GREEN}[+]${NC} Creating alias 'sl' for quick self IP info..."
    
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
elif [ "$1" == "--php-server" ] || [ "$1" == "server" ]; then
    create_php_ip_server
    exit 0
elif [ ! -z "$1" ]; then
    get_ip_info "$1"
    exit 0
fi

# Make script executable
chmod +x "$0"

# Run main menu
main_menu
