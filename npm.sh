# Enhanced Bash Script for node_modules Exposure Detection
# This script specifically focuses on detecting exposed node_modules directories
# Author: AI Assistant

#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/security_scan_results"
THREADS=10
TIMEOUT=15

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_critical() {
    echo -e "${PURPLE}[CRITICAL]${NC} $1"
}

# node_modules exposure test paths
NODE_MODULES_PATHS=(
    "/node_modules/"
    "/node_modules/package.json"
    "/node_modules/react/"
    "/node_modules/angular/"
    "/node_modules/vue/"
    "/node_modules/jquery/"
    "/node_modules/lodash/"
    "/node_modules/express/"
    "/node_modules/.bin/"
    "/assets/node_modules/"
    "/static/node_modules/"
    "/js/node_modules/"
    "/public/node_modules/"
    "/dist/node_modules/"
    "/build/node_modules/"
)

# Directory traversal payloads
TRAVERSAL_PAYLOADS=(
    "../node_modules/"
    "../../node_modules/"
    "../../../node_modules/"
    "..%2fnode_modules%2f"
    "..%252fnode_modules%252f"
    "%2e%2e%2fnode_modules%2f"
    "%252e%252e%252fnode_modules%252f"
    "....//node_modules/"
    "..././node_modules/"
)

# Package.json exposure paths
PACKAGE_JSON_PATHS=(
    "/package.json"
    "/node_modules/package.json"
    "/static/package.json"
    "/assets/package.json"
    "/public/package.json"
    "/dist/package.json"
    "/build/package.json"
)

# Function to test node_modules exposure
test_node_modules_exposure() {
    local base_url="$1"
    local output_file="$2"
    local exposures_found=0
    
    print_status "Testing node_modules exposure for $base_url"
    
    # Test direct paths
    for path in "${NODE_MODULES_PATHS[@]}"; do
        local test_url="${base_url%/}${path}"
        
        # Make request and check response
        local response
        response=$(curl -s -w "%{http_code}" --max-time $TIMEOUT \
            --user-agent "Mozilla/5.0 (Security Scanner)" \
            "$test_url" 2>/dev/null)
        
        local http_code="${response: -3}"
        local content="${response%???}"
        
        if [ "$http_code" = "200" ]; then
            # Check for directory listing indicators
            if echo "$content" | grep -qiE "(index of|directory listing|parent directory|package\.json|node_modules|npm|\.bin)"; then
                print_critical "EXPOSED node_modules found: $test_url"
                echo "{\"type\": \"direct_exposure\", \"url\": \"$test_url\", \"status\": \"$http_code\"}" >> "${output_file}.exposures"
                ((exposures_found++))
            fi
        fi
    done
    
    # Test directory traversal
    for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
        local test_url="${base_url%/}/${payload}"
        
        local response
        response=$(curl -s -w "%{http_code}" --max-time $TIMEOUT \
            --user-agent "Mozilla/5.0 (Security Scanner)" \
            "$test_url" 2>/dev/null)
        
        local http_code="${response: -3}"
        local content="${response%???}"
        
        if [ "$http_code" = "200" ]; then
            if echo "$content" | grep -qiE "(package\.json|node_modules|\.bin|npm)"; then
                print_critical "DIRECTORY TRAVERSAL SUCCESS: $test_url"
                echo "{\"type\": \"traversal_exposure\", \"url\": \"$test_url\", \"status\": \"$http_code\"}" >> "${output_file}.exposures"
                ((exposures_found++))
            fi
        fi
    done
    
    return $exposures_found
}

# Function to test package.json exposure
test_package_json_exposure() {
    local base_url="$1"
    local output_file="$2"
    local exposures_found=0
    
    print_status "Testing package.json exposure for $base_url"
    
    for path in "${PACKAGE_JSON_PATHS[@]}"; do
        local test_url="${base_url%/}${path}"
        
        local response
        response=$(curl -s -w "%{http_code}" --max-time $TIMEOUT \
            --user-agent "Mozilla/5.0 (Security Scanner)" \
            "$test_url" 2>/dev/null)
        
        local http_code="${response: -3}"
        local content="${response%???}"
        
        if [ "$http_code" = "200" ]; then
            # Check if it's valid JSON with package information
            if echo "$content" | jq -e '.name' >/dev/null 2>&1 || \
               echo "$content" | jq -e '.dependencies' >/dev/null 2>&1; then
                print_warning "EXPOSED package.json found: $test_url"
                
                # Extract package name and dependencies
                local pkg_name
                local dependencies
                pkg_name=$(echo "$content" | jq -r '.name // "unknown"' 2>/dev/null)
                dependencies=$(echo "$content" | jq -r '.dependencies // {} | keys | join(",")' 2>/dev/null)
                
                echo "{\"type\": \"package_json\", \"url\": \"$test_url\", \"name\": \"$pkg_name\", \"dependencies\": \"$dependencies\"}" >> "${output_file}.packages"
                ((exposures_found++))
            fi
        fi
    done
    
    return $exposures_found
}

# Function to assess security risk
assess_security_risk() {
    local exposures_file="$1"
    local packages_file="$2"
    
    local risk_score=0
    
    # Count direct exposures (high risk)
    if [ -f "$exposures_file" ]; then
        local direct_exposures
        direct_exposures=$(grep -c "direct_exposure" "$exposures_file" 2>/dev/null || echo "0")
        risk_score=$((risk_score + direct_exposures * 8))
        
        # Count traversal exposures (critical risk)
        local traversal_exposures
        traversal_exposures=$(grep -c "traversal_exposure" "$exposures_file" 2>/dev/null || echo "0")
        risk_score=$((risk_score + traversal_exposures * 10))
    fi
    
    # Count package.json exposures (medium risk)
    if [ -f "$packages_file" ]; then
        local package_exposures
        package_exposures=$(wc -l < "$packages_file" 2>/dev/null || echo "0")
        risk_score=$((risk_score + package_exposures * 6))
    fi
    
    # Determine risk level
    if [ $risk_score -ge 8 ]; then
        echo "HIGH"
    elif [ $risk_score -ge 4 ]; then
        echo "MEDIUM"
    elif [ $risk_score -gt 0 ]; then
        echo "LOW"
    else
        echo "MINIMAL"
    fi
}

# Function to analyze single URL
analyze_url_security() {
    local url="$1"
    local output_file="$2"
    
    print_status "Security analysis for: $url"
    
    # Test node_modules exposure
    test_node_modules_exposure "$url" "$output_file"
    local node_modules_result=$?
    
    # Test package.json exposure  
    test_package_json_exposure "$url" "$output_file"
    local package_json_result=$?
    
    # Assess overall risk
    local risk_level
    risk_level=$(assess_security_risk "${output_file}.exposures" "${output_file}.packages")
    
    # Create result entry
    jq -n \
        --arg url "$url" \
        --arg status "success" \
        --arg risk_level "$risk_level" \
        --argjson node_modules_exposures "$node_modules_result" \
        --argjson package_json_exposures "$package_json_result" \
        '{
            url: $url, 
            status: $status, 
            security_risk: $risk_level,
            node_modules_exposures: $node_modules_exposures,
            package_json_exposures: $package_json_exposures,
            timestamp: now
        }' >> "$output_file"
    
    # Log risk level
    case "$risk_level" in
        "HIGH")
            print_critical "HIGH RISK detected for $url"
            ;;
        "MEDIUM")
            print_warning "MEDIUM RISK detected for $url"
            ;;
        "LOW")
            print_warning "LOW RISK detected for $url"
            ;;
        *)
            print_success "MINIMAL RISK for $url"
            ;;
    esac
}

# Function to process URLs in parallel
process_urls_parallel() {
    local input_file="$1"
    local output_file="$2"
    
    print_status "Processing URLs for security vulnerabilities (max $THREADS threads)"
    
    # Create temporary files for each URL
    local temp_dir="$OUTPUT_DIR/temp_$$"
    mkdir -p "$temp_dir"
    
    # Initialize output files
    echo "[]" > "$output_file"
    
    # Process URLs in parallel
    cat "$input_file" | head -100 | xargs -n 1 -P "$THREADS" -I {} bash -c "
        url='{}'
        temp_file='$temp_dir/\$(echo \$url | md5sum | cut -d' ' -f1)'
        analyze_url_security '\$url' '\$temp_file'
    "
    
    # Combine all results
    find "$temp_dir" -name "*.json" -type f | while read -r file; do
        if [ -s "$file" ]; then
            cat "$file" >> "${output_file}.tmp"
        fi
    done
    
    # Create final JSON array
    if [ -f "${output_file}.tmp" ]; then
        jq -s '.' "${output_file}.tmp" > "$output_file"
        rm "${output_file}.tmp"
    fi
    
    # Combine exposure files
    find "$temp_dir" -name "*.exposures" -type f -exec cat {} \; > "${output_file}.all_exposures" 2>/dev/null
    find "$temp_dir" -name "*.packages" -type f -exec cat {} \; > "${output_file}.all_packages" 2>/dev/null
    
    # Cleanup
    rm -rf "$temp_dir"
}

# Function to generate security summary
generate_security_summary() {
    local results_file="$1"
    local summary_file="$2"
    
    print_status "Generating security summary report"
    
    if [ ! -f "$results_file" ]; then
        print_error "Results file not found: $results_file"
        return 1
    fi
    
    local total_sites
    total_sites=$(jq 'length' "$results_file")
    
    local high_risk
    high_risk=$(jq '[.[] | select(.security_risk == "HIGH")] | length' "$results_file")
    
    local medium_risk
    medium_risk=$(jq '[.[] | select(.security_risk == "MEDIUM")] | length' "$results_file")
    
    local total_node_modules
    total_node_modules=$(jq '[.[] | .node_modules_exposures] | add' "$results_file")
    
    local total_package_json
    total_package_json=$(jq '[.[] | .package_json_exposures] | add' "$results_file")
    
    # Create markdown summary
    cat > "$summary_file" << EOF
# Security Scan Summary Report

## Critical Findings
- **Total Sites Scanned:** $total_sites
- **HIGH RISK Sites:** $high_risk
- **MEDIUM RISK Sites:** $medium_risk
- **node_modules Exposures Found:** $total_node_modules
- **package.json Exposures Found:** $total_package_json

## Risk Distribution
EOF
    
    jq -r '
        group_by(.security_risk) | 
        map({risk: .[0].security_risk, count: length}) | 
        .[] | 
        "- \(.risk): \(.count) sites"
    ' "$results_file" >> "$summary_file"
    
    cat >> "$summary_file" << EOF

## Remediation Recommendations
1. **Immediately** block access to /node_modules/ directories
2. Remove or restrict access to package.json files
3. Implement proper directory traversal protection
4. Review web server configuration for static file serving
5. Use .htaccess or nginx rules to deny node_modules access

## High Risk Sites Requiring Immediate Attention
EOF
    
    jq -r '.[] | select(.security_risk == "HIGH") | "- \(.url)"' "$results_file" >> "$summary_file"
    
    print_success "Security summary saved to: $summary_file"
}

# Main function
main() {
    local input_file=""
    local output_format="json"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--input)
                input_file="$2"
                shift 2
                ;;
            -f|--format)
                output_format="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 -i input_file [options]"
                echo "Options:"
                echo "  -i, --input FILE    Input file with URLs (one per line)"
                echo "  -f, --format FORMAT Output format (json|csv)"
                echo "  -t, --threads NUM   Number of parallel threads (default: 10)"
                echo "  --timeout SEC       Request timeout in seconds (default: 15)"
                echo "  -h, --help          Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Validate input
    if [ -z "$input_file" ]; then
        print_error "Input file is required. Use -i or --input option."
        exit 1
    fi
    
    if [ ! -f "$input_file" ]; then
        print_error "Input file '$input_file' not found."
        exit 1
    fi
    
    # Check dependencies
    if ! command -v curl &> /dev/null; then
        print_error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        print_error "jq is required but not installed"
        exit 1
    fi
    
    # Setup output files
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local results_file="$OUTPUT_DIR/security_scan_$timestamp.json"
    local summary_file="$OUTPUT_DIR/security_summary_$timestamp.md"
    
    print_status "Starting SECURITY-FOCUSED node_modules exposure detection"
    print_status "Input file: $input_file"
    print_status "Output directory: $OUTPUT_DIR"
    print_status "Using $THREADS parallel threads"
    
    # Process URLs
    process_urls_parallel "$input_file" "$results_file"
    
    # Generate security summary
    generate_security_summary "$results_file" "$summary_file"
    
    # Convert to CSV if requested
    if [ "$output_format" = "csv" ]; then
        local csv_file="${results_file%.json}.csv"
        print_status "Converting results to CSV format"
        
        echo "URL,Security_Risk,Node_Modules_Exposures,Package_JSON_Exposures,Status" > "$csv_file"
        jq -r '.[] | [.url, .security_risk, .node_modules_exposures, .package_json_exposures, .status] | @csv' "$results_file" >> "$csv_file"
        
        print_success "CSV results saved to: $csv_file"
    fi
    
    print_success "Security scan complete!"
    print_success "Results saved to: $results_file"
    print_success "Summary saved to: $summary_file"
    
    # Show final statistics
    local high_risk_count
    high_risk_count=$(jq '[.[] | select(.security_risk == "HIGH")] | length' "$results_file" 2>/dev/null || echo "0")
    
    if [ "$high_risk_count" -gt 0 ]; then
        print_critical "ALERT: $high_risk_count HIGH RISK sites found with node_modules exposure!"
    else
        print_success "No critical node_modules exposures detected."
    fi
}

# Run main function with all arguments
main "$@"
