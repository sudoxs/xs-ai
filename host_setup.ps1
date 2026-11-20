<#
.SYNOPSIS
    xs-ai Host Setup — prepares Windows as the AI backend for pentest sessions.

.DESCRIPTION
    - Checks Ollama installation and required models
    - Configures Ollama to listen on all interfaces (Host-only network)
    - Adds Windows Firewall rule for port 11434
    - Starts the Ollama service
    - Shows connection info for the client

.USAGE
    Run in an elevated PowerShell:
        .\host_setup.ps1

    To specify models:
        .\host_setup.ps1 -PlannerModel "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest" -ExecutorModel "qwen2.5-coder:7b"
#>

param(
    [string]$PlannerModel = "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest",
    [string]$ExecutorModel = "qwen2.5-coder:7b",
    [int]$Port = 11434,
    [switch]$SkipFirewall
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "    [FAIL] $msg" -ForegroundColor Red }

# --- 1. Check Ollama ---
Write-Step "Checking Ollama installation"
$ollamaCmd = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollamaCmd) {
    Write-Fail "Ollama is not installed or not in PATH."
    Write-Host "    Download from: https://ollama.com/download/windows"
    exit 1
}
$ver = & ollama --version 2>&1
Write-Ok "Ollama found: $ver"

# --- 2. Check/pull models ---
Write-Step "Checking required models"
$installedRaw = & ollama list 2>&1
$installed = ($installedRaw | Out-String)

foreach ($model in @($PlannerModel, $ExecutorModel)) {
    $shortName = ($model -split ":")[0]
    if ($installed -match [regex]::Escape($shortName)) {
        Write-Ok "Model present: $model"
    } else {
        Write-Warn "Model not found locally: $model"
        $answer = Read-Host "    Pull it now? (yes/no)"
        if ($answer -eq "yes") {
            Write-Host "    Pulling $model (this may take a while)..."
            & ollama pull $model
            if ($LASTEXITCODE -ne 0) {
                Write-Fail "Failed to pull $model"
                exit 1
            }
            Write-Ok "Pulled $model"
        } else {
            Write-Warn "Skipped. The client will fail if this model is unavailable."
        }
    }
}

# --- 3. Configure Ollama to listen on all interfaces ---
Write-Step "Configuring Ollama network binding"

$currentBind = [System.Environment]::GetEnvironmentVariable("OLLAMA_HOST", "User")
$desiredBind = "0.0.0.0:$Port"

if ($currentBind -eq $desiredBind) {
    Write-Ok "OLLAMA_HOST already set to $desiredBind"
} else {
    if ($currentBind) {
        Write-Warn "Current OLLAMA_HOST = $currentBind"
    }
    Write-Host "    Setting OLLAMA_HOST = $desiredBind (user environment variable)"
    [System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", $desiredBind, "User")
    $env:OLLAMA_HOST = $desiredBind
    Write-Ok "OLLAMA_HOST set. Ollama will listen on all interfaces, port $Port."
    Write-Warn "Ollama must be restarted for this to take effect."
}

# --- 4. Firewall rule ---
if (-not $SkipFirewall) {
    Write-Step "Checking Windows Firewall rule"
    $ruleName = "xs-ai Ollama (TCP $Port)"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Ok "Firewall rule already exists: $ruleName"
    } else {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Warn "Not running as Administrator. Cannot add firewall rule."
            Write-Host "    Run this script as Administrator, or add the rule manually:"
            Write-Host "    New-NetFirewallRule -DisplayName '$ruleName' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Private"
        } else {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Private | Out-Null
            Write-Ok "Firewall rule added: $ruleName (Private profile only)"
        }
    }
} else {
    Write-Step "Skipping firewall setup (-SkipFirewall)"
}

# --- 5. Restart Ollama ---
Write-Step "Restarting Ollama service"
$ollamaProc = Get-Process -Name "ollama*" -ErrorAction SilentlyContinue
if ($ollamaProc) {
    Write-Host "    Stopping existing Ollama processes..."
    $ollamaProc | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Write-Host "    Starting Ollama serve in background..."
$env:OLLAMA_HOST = $desiredBind
Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Minimized
Start-Sleep -Seconds 3

# --- 6. Verify ---
Write-Step "Verifying Ollama API"
try {
    $response = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/tags" -TimeoutSec 5
    $modelNames = ($response.models | ForEach-Object { $_.name }) -join ", "
    Write-Ok "API responding. Models: $modelNames"
} catch {
    Write-Warn "API not responding yet on localhost:$Port. It may need a few more seconds."
}

# --- 7. Show connection info ---
Write-Step "Connection info for client (Kali)"

$hostIPs = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object IPAddress, InterfaceAlias

Write-Host ""
Write-Host "    Available host IPs:" -ForegroundColor White
foreach ($ip in $hostIPs) {
    Write-Host "      $($ip.IPAddress)  ($($ip.InterfaceAlias))"
}

Write-Host ""
Write-Host "    On Kali, test with:" -ForegroundColor White
foreach ($ip in $hostIPs) {
    Write-Host "      curl -sS http://$($ip.IPAddress):$Port/api/tags"
}

Write-Host ""
Write-Host "    Then run the client:" -ForegroundColor White
Write-Host "      python3 client.py --host <WINDOWS_IP>" -ForegroundColor Yellow
Write-Host ""
Write-Ok "Host setup complete."
