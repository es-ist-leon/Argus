# Argus RMT - Certificate Generation Script
# PowerShell script to generate TLS certificates for server and agents

param(
    [string]$OutputDir = ".\certs",
    [string]$CAName = "Argus CA",
    [string]$ServerName = "argus-server",
    [string]$ServerIP = "127.0.0.1",
    [int]$ValidDays = 365,
    [string[]]$AgentNames = @(),
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Info($message) {
    Write-Host "[INFO] $message" -ForegroundColor Cyan
}

function Write-Success($message) {
    Write-Host "[SUCCESS] $message" -ForegroundColor Green
}

function Write-Warning($message) {
    Write-Host "[WARNING] $message" -ForegroundColor Yellow
}

# Check for OpenSSL
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    Write-Error "OpenSSL not found. Please install OpenSSL and add it to PATH."
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Info "Created output directory: $OutputDir"
}

$caKeyPath = Join-Path $OutputDir "ca.key"
$caCertPath = Join-Path $OutputDir "ca.crt"
$serverKeyPath = Join-Path $OutputDir "server.key"
$serverCsrPath = Join-Path $OutputDir "server.csr"
$serverCertPath = Join-Path $OutputDir "server.crt"

# Check if CA already exists
if ((Test-Path $caKeyPath) -and (Test-Path $caCertPath) -and -not $Force) {
    Write-Warning "CA certificate already exists. Use -Force to regenerate."
} else {
    Write-Info "Generating CA private key..."
    & openssl genrsa -out $caKeyPath 4096
    
    Write-Info "Generating CA certificate..."
    & openssl req -new -x509 -days ($ValidDays * 3) -key $caKeyPath -out $caCertPath `
        -subj "/C=US/ST=State/L=City/O=Argus RMT/CN=$CAName"
    
    Write-Success "CA certificate generated: $caCertPath"
}

# Create server certificate config
$serverConfigPath = Join-Path $OutputDir "server.cnf"
$serverConfig = @"
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
ST = State
L = City
O = Argus RMT
CN = $ServerName

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $ServerName
DNS.2 = localhost
IP.1 = $ServerIP
IP.2 = 127.0.0.1
"@
Set-Content -Path $serverConfigPath -Value $serverConfig

# Check if server cert already exists
if ((Test-Path $serverKeyPath) -and (Test-Path $serverCertPath) -and -not $Force) {
    Write-Warning "Server certificate already exists. Use -Force to regenerate."
} else {
    Write-Info "Generating server private key..."
    & openssl genrsa -out $serverKeyPath 2048
    
    Write-Info "Generating server CSR..."
    & openssl req -new -key $serverKeyPath -out $serverCsrPath -config $serverConfigPath
    
    Write-Info "Signing server certificate with CA..."
    & openssl x509 -req -in $serverCsrPath -CA $caCertPath -CAkey $caKeyPath `
        -CAcreateserial -out $serverCertPath -days $ValidDays `
        -extfile $serverConfigPath -extensions req_ext
    
    # Cleanup CSR
    Remove-Item $serverCsrPath -Force
    Remove-Item $serverConfigPath -Force
    
    Write-Success "Server certificate generated: $serverCertPath"
}

# Generate agent certificates
function New-AgentCertificate($agentName) {
    $agentKeyPath = Join-Path $OutputDir "agent-$agentName.key"
    $agentCsrPath = Join-Path $OutputDir "agent-$agentName.csr"
    $agentCertPath = Join-Path $OutputDir "agent-$agentName.crt"
    
    if ((Test-Path $agentKeyPath) -and (Test-Path $agentCertPath) -and -not $Force) {
        Write-Warning "Agent certificate for '$agentName' already exists. Use -Force to regenerate."
        return
    }
    
    Write-Info "Generating agent certificate for: $agentName"
    
    # Generate agent key
    & openssl genrsa -out $agentKeyPath 2048
    
    # Generate CSR
    & openssl req -new -key $agentKeyPath -out $agentCsrPath `
        -subj "/C=US/ST=State/L=City/O=Argus RMT/CN=$agentName"
    
    # Sign with CA
    & openssl x509 -req -in $agentCsrPath -CA $caCertPath -CAkey $caKeyPath `
        -CAcreateserial -out $agentCertPath -days $ValidDays
    
    # Cleanup CSR
    Remove-Item $agentCsrPath -Force
    
    Write-Success "Agent certificate generated: $agentCertPath"
}

# Generate agent certificates if specified
foreach ($agent in $AgentNames) {
    New-AgentCertificate $agent
}

# Generate a generic agent certificate if no specific agents specified
if ($AgentNames.Count -eq 0) {
    New-AgentCertificate "agent"
}

# Display summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Certificate Generation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Generated files in: $OutputDir"
Write-Host ""
Write-Host "CA Certificate:     ca.crt"
Write-Host "CA Key:             ca.key (keep secure!)"
Write-Host "Server Certificate: server.crt"
Write-Host "Server Key:         server.key"
Write-Host ""
Write-Host "Agent Certificates:" -ForegroundColor Yellow
Get-ChildItem $OutputDir -Filter "agent-*.crt" | ForEach-Object {
    Write-Host "  - $($_.Name)"
}
Write-Host ""
Write-Host "Usage in configuration:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Server config (configs/server.yaml):" -ForegroundColor Cyan
Write-Host "  tls:"
Write-Host "    enabled: true"
Write-Host "    cert_file: `"certs/server.crt`""
Write-Host "    key_file: `"certs/server.key`""
Write-Host "    ca_file: `"certs/ca.crt`""
Write-Host "    client_auth: true"
Write-Host ""
Write-Host "Agent config (configs/agent.yaml):" -ForegroundColor Cyan
Write-Host "  tls:"
Write-Host "    enabled: true"
Write-Host "    ca_cert: `"certs/ca.crt`""
Write-Host "    client_cert: `"certs/agent.crt`""
Write-Host "    client_key: `"certs/agent.key`""
Write-Host ""

# Verify certificates
Write-Info "Verifying certificates..."
$verification = & openssl verify -CAfile $caCertPath $serverCertPath 2>&1
if ($verification -match "OK") {
    Write-Success "Server certificate verification: OK"
} else {
    Write-Warning "Server certificate verification failed: $verification"
}

foreach ($agentCert in (Get-ChildItem $OutputDir -Filter "agent-*.crt")) {
    $verification = & openssl verify -CAfile $caCertPath $agentCert.FullName 2>&1
    if ($verification -match "OK") {
        Write-Success "Agent certificate verification ($($agentCert.Name)): OK"
    } else {
        Write-Warning "Agent certificate verification failed: $verification"
    }
}
