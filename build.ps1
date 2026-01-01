# Build script for Windows

param(
    [Parameter(Position=0)]
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"

$BuildDir = "bin"
$NativeBuildDir = "native\build"
$ServerBinary = "$BuildDir\argus-server.exe"
$AgentBinary = "$BuildDir\argus-agent.exe"

function Write-Header($message) {
    Write-Host "`n=== $message ===" -ForegroundColor Cyan
}

function Build-Native {
    Write-Header "Building Native Modules (C++)"
    
    if (-not (Test-Path $NativeBuildDir)) {
        New-Item -ItemType Directory -Path $NativeBuildDir -Force | Out-Null
    }
    
    Push-Location $NativeBuildDir
    try {
        cmake ..
        cmake --build . --config Release
    } finally {
        Pop-Location
    }
    
    Write-Host "Native modules built successfully" -ForegroundColor Green
}

function Build-Server {
    Write-Header "Building Server (Go)"
    
    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
    }
    
    go build -o $ServerBinary -v ./cmd/server
    Write-Host "Server built: $ServerBinary" -ForegroundColor Green
}

function Build-Agent {
    Write-Header "Building Agent (Go)"
    
    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
    }
    
    go build -o $AgentBinary -v ./cmd/agent
    Write-Host "Agent built: $AgentBinary" -ForegroundColor Green
}

function Build-All {
    Build-Native
    Build-Server
    Build-Agent
    Write-Host "`nBuild completed successfully!" -ForegroundColor Green
}

function Get-Dependencies {
    Write-Header "Downloading Dependencies"
    go mod download
    go mod tidy
    Write-Host "Dependencies downloaded" -ForegroundColor Green
}

function Invoke-Tests {
    Write-Header "Running Tests"
    go test -v ./...
}

function Clear-Build {
    Write-Header "Cleaning Build Artifacts"
    
    if (Test-Path $BuildDir) {
        Remove-Item -Recurse -Force $BuildDir
    }
    if (Test-Path $NativeBuildDir) {
        Remove-Item -Recurse -Force $NativeBuildDir
    }
    
    go clean
    Write-Host "Clean completed" -ForegroundColor Green
}

function New-Certificates {
    Write-Header "Generating Development Certificates"
    
    if (-not (Test-Path "certs")) {
        New-Item -ItemType Directory -Path "certs" -Force | Out-Null
    }
    
    # Generate CA
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 `
        -keyout certs/ca.key -out certs/ca.crt `
        -subj "/CN=Argus CA/O=Argus"
    
    # Generate server certificate
    openssl req -nodes -newkey rsa:2048 `
        -keyout certs/server.key -out certs/server.csr `
        -subj "/CN=localhost/O=Argus"
    
    openssl x509 -req -days 365 `
        -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key `
        -CAcreateserial -out certs/server.crt
    
    # Generate agent certificate
    openssl req -nodes -newkey rsa:2048 `
        -keyout certs/agent.key -out certs/agent.csr `
        -subj "/CN=agent/O=Argus"
    
    openssl x509 -req -days 365 `
        -in certs/agent.csr -CA certs/ca.crt -CAkey certs/ca.key `
        -CAcreateserial -out certs/agent.crt
    
    Remove-Item certs/*.csr, certs/*.srl -ErrorAction SilentlyContinue
    
    Write-Host "Certificates generated in certs/" -ForegroundColor Green
}

function Start-Server {
    Build-Server
    Write-Header "Starting Server"
    & $ServerBinary --listen :8443 --api :8080
}

function Start-Agent {
    Build-Agent
    Write-Header "Starting Agent"
    & $AgentBinary --server localhost:8443
}

function Show-Help {
    Write-Host @"

Argus Build Script for Windows

Usage: .\build.ps1 [target]

Targets:
    all          Build everything (default)
    native       Build C++ native modules only
    server       Build Go server only
    agent        Build Go agent only
    deps         Download Go dependencies
    test         Run tests
    clean        Remove build artifacts
    certs        Generate development TLS certificates
    run-server   Build and run server
    run-agent    Build and run agent
    help         Show this help message

Examples:
    .\build.ps1              # Build all components
    .\build.ps1 server       # Build server only
    .\build.ps1 run-server   # Build and run server

"@
}

# Main execution
switch ($Target.ToLower()) {
    "all"        { Build-All }
    "native"     { Build-Native }
    "server"     { Build-Server }
    "agent"      { Build-Agent }
    "deps"       { Get-Dependencies }
    "test"       { Invoke-Tests }
    "clean"      { Clear-Build }
    "certs"      { New-Certificates }
    "run-server" { Start-Server }
    "run-agent"  { Start-Agent }
    "help"       { Show-Help }
    default      { 
        Write-Host "Unknown target: $Target" -ForegroundColor Red
        Show-Help
        exit 1
    }
}
