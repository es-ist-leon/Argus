# Argus RMT - Agent Installation Script
# PowerShell script to install the Argus agent on Windows/Linux

param(
    [Parameter(Mandatory=$false)]
    [string]$ServerAddress = "",
    
    [Parameter(Mandatory=$false)]
    [string]$InstallDir = "",
    
    [Parameter(Mandatory=$false)]
    [string]$AgentID = "",
    
    [Parameter(Mandatory=$false)]
    [hashtable]$Labels = @{},
    
    [Parameter(Mandatory=$false)]
    [string]$CACertPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$AgentCertPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$AgentKeyPath = "",
    
    [switch]$NoTLS,
    [switch]$InstallService,
    [switch]$StartService,
    [switch]$Uninstall,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Default paths based on OS
if ($IsLinux -or $IsMacOS) {
    $DefaultInstallDir = "/opt/argus"
    $ConfigDir = "/etc/argus"
    $LogDir = "/var/log/argus"
    $BinaryName = "argus-agent"
    $ServiceFile = "/etc/systemd/system/argus-agent.service"
} else {
    $DefaultInstallDir = "C:\Program Files\Argus"
    $ConfigDir = "C:\ProgramData\Argus"
    $LogDir = "C:\ProgramData\Argus\logs"
    $BinaryName = "argus-agent.exe"
}

if (-not $InstallDir) {
    $InstallDir = $DefaultInstallDir
}

function Write-Info($message) {
    Write-Host "[INFO] $message" -ForegroundColor Cyan
}

function Write-Success($message) {
    Write-Host "[SUCCESS] $message" -ForegroundColor Green
}

function Write-Warning($message) {
    Write-Host "[WARNING] $message" -ForegroundColor Yellow
}

function Write-Error($message) {
    Write-Host "[ERROR] $message" -ForegroundColor Red
}

# Uninstall function
function Uninstall-Agent {
    Write-Info "Uninstalling Argus Agent..."
    
    if ($IsLinux -or $IsMacOS) {
        # Stop and disable service
        if (Test-Path "/etc/systemd/system/argus-agent.service") {
            Write-Info "Stopping service..."
            sudo systemctl stop argus-agent 2>$null
            sudo systemctl disable argus-agent 2>$null
            sudo rm -f /etc/systemd/system/argus-agent.service
            sudo systemctl daemon-reload
        }
        
        # Remove files
        Write-Info "Removing files..."
        sudo rm -rf $InstallDir
        sudo rm -rf $ConfigDir
        
    } else {
        # Windows
        $service = Get-Service -Name "ArgusAgent" -ErrorAction SilentlyContinue
        if ($service) {
            Write-Info "Stopping service..."
            Stop-Service -Name "ArgusAgent" -Force -ErrorAction SilentlyContinue
            Write-Info "Removing service..."
            sc.exe delete ArgusAgent
        }
        
        # Remove files
        Write-Info "Removing files..."
        if (Test-Path $InstallDir) {
            Remove-Item -Path $InstallDir -Recurse -Force
        }
        if (Test-Path $ConfigDir) {
            Remove-Item -Path $ConfigDir -Recurse -Force
        }
    }
    
    Write-Success "Argus Agent uninstalled successfully!"
    exit 0
}

if ($Uninstall) {
    Uninstall-Agent
}

# Check if running as admin/root
if ($IsLinux -or $IsMacOS) {
    if ((id -u) -ne 0) {
        Write-Error "This script must be run as root (use sudo)"
        exit 1
    }
} else {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run as Administrator"
        exit 1
    }
}

# Validate server address
if (-not $ServerAddress) {
    $ServerAddress = Read-Host "Enter server address (e.g., server.example.com:8443)"
}

if (-not $ServerAddress) {
    Write-Error "Server address is required"
    exit 1
}

Write-Info "Installing Argus Agent..."
Write-Info "  Server: $ServerAddress"
Write-Info "  Install Dir: $InstallDir"
Write-Info "  Config Dir: $ConfigDir"

# Create directories
Write-Info "Creating directories..."
if ($IsLinux -or $IsMacOS) {
    sudo mkdir -p $InstallDir
    sudo mkdir -p $ConfigDir
    sudo mkdir -p $LogDir
    sudo mkdir -p "$ConfigDir/certs"
} else {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    New-Item -ItemType Directory -Path "$ConfigDir\certs" -Force | Out-Null
}

# Copy certificates if provided
if ($CACertPath -and (Test-Path $CACertPath)) {
    Write-Info "Copying CA certificate..."
    if ($IsLinux -or $IsMacOS) {
        sudo cp $CACertPath "$ConfigDir/certs/ca.crt"
    } else {
        Copy-Item $CACertPath "$ConfigDir\certs\ca.crt"
    }
}

if ($AgentCertPath -and (Test-Path $AgentCertPath)) {
    Write-Info "Copying agent certificate..."
    if ($IsLinux -or $IsMacOS) {
        sudo cp $AgentCertPath "$ConfigDir/certs/agent.crt"
    } else {
        Copy-Item $AgentCertPath "$ConfigDir\certs\agent.crt"
    }
}

if ($AgentKeyPath -and (Test-Path $AgentKeyPath)) {
    Write-Info "Copying agent key..."
    if ($IsLinux -or $IsMacOS) {
        sudo cp $AgentKeyPath "$ConfigDir/certs/agent.key"
        sudo chmod 600 "$ConfigDir/certs/agent.key"
    } else {
        Copy-Item $AgentKeyPath "$ConfigDir\certs\agent.key"
    }
}

# Generate agent ID if not provided
if (-not $AgentID) {
    $AgentID = [guid]::NewGuid().ToString()
    Write-Info "Generated Agent ID: $AgentID"
}

# Build labels string
$labelsYaml = ""
foreach ($key in $Labels.Keys) {
    $labelsYaml += "    $key`: `"$($Labels[$key])`"`n"
}
if (-not $labelsYaml) {
    $labelsYaml = "    # Add labels here`n"
}

# Generate configuration file
$tlsEnabled = -not $NoTLS
$tlsConfig = if ($tlsEnabled) {
@"
    tls:
      enabled: true
      ca_cert: "$($IsLinux ? "$ConfigDir/certs/ca.crt" : "$ConfigDir\certs\ca.crt")"
      client_cert: "$($IsLinux ? "$ConfigDir/certs/agent.crt" : "$ConfigDir\certs\agent.crt")"
      client_key: "$($IsLinux ? "$ConfigDir/certs/agent.key" : "$ConfigDir\certs\agent.key")"
      insecure_skip_verify: false
"@
} else {
@"
    tls:
      enabled: false
"@
}

$configContent = @"
# Argus Agent Configuration
# Generated by install script on $(Get-Date)

agent:
  id: "$AgentID"
  
  server:
    addr: "$ServerAddress"
$tlsConfig
  
  connection:
    heartbeat_interval: "30s"
    reconnect_interval: "10s"
    reconnect_max_attempts: 0
    connect_timeout: "30s"
    
  labels:
$labelsYaml
    
  capabilities:
    - "execute"
    - "file_transfer"
    - "system_info"
    - "process_list"
    - "process_kill"
    - "service_manage"
    - "shell_session"
    
  security:
    allowed_commands: []
    blocked_commands:
      - "^rm -rf /.*"
      - "^dd.*"
      - "^mkfs.*"
    file_transfer:
      allowed_paths:
        - "/var/log"
        - "/tmp"
      blocked_paths:
        - "/etc/shadow"
        - "~/.ssh"
      max_file_size: "100MB"

native:
  enabled: true
  library_path: ""

logging:
  level: "info"
  format: "json"
  output: "file"
  file: "$($IsLinux ? "$LogDir/agent.log" : "$LogDir\agent.log")"

resources:
  max_cpu_percent: 10
  max_memory_mb: 256
  max_concurrent_commands: 5
"@

$configPath = if ($IsLinux -or $IsMacOS) { "$ConfigDir/agent.yaml" } else { "$ConfigDir\agent.yaml" }

Write-Info "Writing configuration file..."
if ($IsLinux -or $IsMacOS) {
    $configContent | sudo tee $configPath > /dev/null
} else {
    Set-Content -Path $configPath -Value $configContent
}

# Find agent binary
$binaryPath = Join-Path $InstallDir $BinaryName
$sourceBinary = $null

# Look for binary in current directory or bin directory
$searchPaths = @(
    ".\$BinaryName",
    ".\bin\$BinaryName",
    "..\bin\$BinaryName",
    ".\build\$BinaryName"
)

foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        $sourceBinary = $path
        break
    }
}

if ($sourceBinary) {
    Write-Info "Copying agent binary from $sourceBinary..."
    if ($IsLinux -or $IsMacOS) {
        sudo cp $sourceBinary $binaryPath
        sudo chmod +x $binaryPath
    } else {
        Copy-Item $sourceBinary $binaryPath
    }
} else {
    Write-Warning "Agent binary not found. Please copy '$BinaryName' to '$InstallDir' manually."
}

# Install service
if ($InstallService) {
    Write-Info "Installing service..."
    
    if ($IsLinux -or $IsMacOS) {
        # Create systemd service file
        $serviceContent = @"
[Unit]
Description=Argus Remote Management Agent
After=network.target

[Service]
Type=simple
ExecStart=$binaryPath -config $configPath
Restart=always
RestartSec=10
User=root
WorkingDirectory=$InstallDir

[Install]
WantedBy=multi-user.target
"@
        $serviceContent | sudo tee $ServiceFile > /dev/null
        sudo systemctl daemon-reload
        sudo systemctl enable argus-agent
        
        Write-Success "Systemd service installed: argus-agent"
        
        if ($StartService) {
            Write-Info "Starting service..."
            sudo systemctl start argus-agent
            sudo systemctl status argus-agent
        }
        
    } else {
        # Windows service using NSSM or native service
        Write-Info "Creating Windows service..."
        
        # Try using NSSM if available
        $nssm = Get-Command nssm -ErrorAction SilentlyContinue
        if ($nssm) {
            & nssm install ArgusAgent $binaryPath
            & nssm set ArgusAgent AppParameters "-config `"$configPath`""
            & nssm set ArgusAgent AppDirectory $InstallDir
            & nssm set ArgusAgent DisplayName "Argus Remote Management Agent"
            & nssm set ArgusAgent Description "Remote management agent for Argus RMT"
            & nssm set ArgusAgent Start SERVICE_AUTO_START
            & nssm set ArgusAgent AppStdout "$LogDir\stdout.log"
            & nssm set ArgusAgent AppStderr "$LogDir\stderr.log"
            
            Write-Success "Windows service installed using NSSM"
        } else {
            # Use sc.exe for basic service creation
            $escapedPath = "`"$binaryPath`" -config `"$configPath`""
            sc.exe create ArgusAgent binPath= $escapedPath start= auto displayname= "Argus Remote Management Agent"
            sc.exe description ArgusAgent "Remote management agent for Argus RMT"
            
            Write-Success "Windows service installed"
            Write-Warning "Consider using NSSM for better service management"
        }
        
        if ($StartService) {
            Write-Info "Starting service..."
            Start-Service -Name "ArgusAgent"
            Get-Service -Name "ArgusAgent"
        }
    }
}

# Display summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Argus Agent Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Installation Summary:"
Write-Host "  Agent ID:     $AgentID"
Write-Host "  Server:       $ServerAddress"
Write-Host "  Install Dir:  $InstallDir"
Write-Host "  Config File:  $configPath"
Write-Host "  TLS Enabled:  $tlsEnabled"
Write-Host ""

if (-not $sourceBinary) {
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Copy the agent binary to: $binaryPath"
    Write-Host "  2. Copy certificates to: $ConfigDir/certs/"
    Write-Host "  3. Start the agent manually or install as service"
    Write-Host ""
}

if ($InstallService) {
    Write-Host "Service Management:" -ForegroundColor Yellow
    if ($IsLinux -or $IsMacOS) {
        Write-Host "  Start:   sudo systemctl start argus-agent"
        Write-Host "  Stop:    sudo systemctl stop argus-agent"
        Write-Host "  Status:  sudo systemctl status argus-agent"
        Write-Host "  Logs:    sudo journalctl -u argus-agent -f"
    } else {
        Write-Host "  Start:   Start-Service ArgusAgent"
        Write-Host "  Stop:    Stop-Service ArgusAgent"
        Write-Host "  Status:  Get-Service ArgusAgent"
    }
} else {
    Write-Host "Manual Start:" -ForegroundColor Yellow
    Write-Host "  $binaryPath -config $configPath"
}

Write-Host ""
