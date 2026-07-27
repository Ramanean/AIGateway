# bifrost-auth.ps1 — Client-side helper for Claude Code + Bifrost via AWS SSO (Windows).
#
# What it does:
#   1. Ensures you have a valid AWS SSO session (opens browser if expired)
#   2. Calls the Lambda broker (signed with your SSO credentials via boto3)
#   3. Writes the virtual key into Claude Code's settings.json
#   4. Verifies the key works with a lightweight API call
#
# Usage:
#   .\bifrost-auth.ps1                 # interactive — opens browser for SSO
#   .\bifrost-auth.ps1 -Check          # just check if current key is valid
#   .\bifrost-auth.ps1 -KeyOnly        # print key to stdout (for apiKeyHelper)

param(
    [switch]$Check,
    [switch]$KeyOnly
)

$ErrorActionPreference = "Stop"

# ── Configuration ──────────────────────────────────────────────────────
$SSO_PROFILE  = if ($env:SSO_PROFILE)  { $env:SSO_PROFILE }  else { "bifrost" }
$BROKER_URL   = if ($env:BROKER_URL)   { $env:BROKER_URL }   else { "https://CHANGEME.lambda-url.us-east-1.on.aws/" }
$BIFROST_URL  = if ($env:BIFROST_URL)  { $env:BIFROST_URL }  else { "https://bifrost.mycompany.com" }
$SETTINGS     = if ($env:CLAUDE_SETTINGS) { $env:CLAUDE_SETTINGS } else { "$env:USERPROFILE\.claude\settings.json" }
# ───────────────────────────────────────────────────────────────────────

function Write-Info  { param($msg) if (-not $KeyOnly) { Write-Host "[+] $msg" -ForegroundColor Green } }
function Write-Warn  { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[x] $msg" -ForegroundColor Red; exit 1 }

# ── Dependency check ──────────────────────────────────────────────────
foreach ($cmd in @("aws", "python")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Fail "'$cmd' is required but not found in PATH."
    }
}

# ── Step 1: Ensure valid AWS SSO session ──────────────────────────────
function Ensure-SSOSession {
    $result = aws sts get-caller-identity --profile $SSO_PROFILE 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Info "AWS SSO session is active."
        return
    }

    if ($KeyOnly) {
        Write-Host "ERROR: SSO session expired. Run 'aws sso login --profile $SSO_PROFILE' first." -ForegroundColor Red
        exit 1
    }

    Write-Warn "SSO session expired or missing. Opening browser for sign-in..."
    aws sso login --profile $SSO_PROFILE
    if ($LASTEXITCODE -ne 0) { Write-Fail "SSO login did not succeed." }
    Write-Info "SSO login successful."
}

# ── Step 2: Call the Lambda broker (SigV4-signed via boto3) ───────────
function Get-VirtualKey {
    Write-Info "Requesting virtual key from broker..."

    $pyScript = @"
import sys, json, boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import urllib.request

url = sys.argv[1]
profile = sys.argv[2]

session = boto3.Session(profile_name=profile)
creds = session.get_credentials().get_frozen_credentials()
region = session.region_name or "us-east-1"

req = AWSRequest(method="POST", url=url, data="{}", headers={"Content-Type": "application/json"})
SigV4Auth(creds, "lambda", region).add_auth(req)

http_req = urllib.request.Request(url, data=b"{}", method="POST")
for k, v in req.headers.items():
    http_req.add_header(k, v)

with urllib.request.urlopen(http_req, timeout=15) as resp:
    body = json.loads(resp.read())
    print(json.dumps(body))
"@

    $tempPy = [System.IO.Path]::GetTempFileName() + ".py"
    $pyScript | Out-File -FilePath $tempPy -Encoding utf8

    try {
        $response = python $tempPy $BROKER_URL $SSO_PROFILE 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Broker call failed: $response"
        }
    }
    finally {
        Remove-Item $tempPy -ErrorAction SilentlyContinue
    }

    try {
        $parsed = $response | ConvertFrom-Json
    }
    catch {
        Write-Fail "Could not parse broker response: $response"
    }

    if ($parsed.error) {
        Write-Fail "Broker error: $($parsed.error)"
    }

    if (-not $parsed.virtual_key) {
        Write-Fail "No virtual_key in broker response."
    }

    Write-Info "Got virtual key for $($parsed.email)"
    return $parsed.virtual_key
}

# ── Step 3: Write to Claude Code settings ─────────────────────────────
function Write-Settings {
    param($vk)

    $dir = Split-Path $SETTINGS -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    if (-not (Test-Path $SETTINGS)) {
        "{}" | Out-File $SETTINGS -Encoding utf8
    }

    $json = Get-Content $SETTINGS -Raw | ConvertFrom-Json

    if (-not $json.env) {
        $json | Add-Member -Name "env" -Value ([pscustomobject]@{}) -MemberType NoteProperty
    }

    $json.env | Add-Member -Name "ANTHROPIC_BASE_URL" -Value "$BIFROST_URL/anthropic" -MemberType NoteProperty -Force
    $json.env | Add-Member -Name "ANTHROPIC_AUTH_TOKEN" -Value $vk -MemberType NoteProperty -Force

    $json | ConvertTo-Json -Depth 20 | Out-File $SETTINGS -Encoding utf8

    Write-Info "Updated $SETTINGS"
}

# ── Step 4: Verify the key works ──────────────────────────────────────
function Test-Key {
    param($vk)
    Write-Info "Verifying key against Bifrost..."

    $body = @{
        model      = "claude-haiku-4-5"
        max_tokens = 1
        messages   = @(@{ role = "user"; content = "hi" })
    } | ConvertTo-Json -Depth 5

    try {
        $resp = Invoke-WebRequest -Uri "$BIFROST_URL/anthropic/v1/messages" `
            -Method POST `
            -Headers @{ "x-api-key" = $vk; "Content-Type" = "application/json" } `
            -Body $body `
            -UseBasicParsing `
            -ErrorAction Stop
        Write-Info "Key is valid. Claude Code is now routed through Bifrost."
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        switch ($status) {
            401     { Write-Fail "Key was rejected (401). It may have been revoked." }
            429     { Write-Info "Key is valid (rate-limited, which confirms auth works)." }
            default { Write-Warn "Bifrost returned HTTP $status. Key saved but may not be valid." }
        }
    }
}

# ── Check mode ────────────────────────────────────────────────────────
if ($Check) {
    if (-not (Test-Path $SETTINGS)) { Write-Fail "No settings file at $SETTINGS" }
    $existing = (Get-Content $SETTINGS -Raw | ConvertFrom-Json)
    $existingVk = $existing.env.ANTHROPIC_AUTH_TOKEN
    if (-not $existingVk) { Write-Fail "No ANTHROPIC_AUTH_TOKEN in settings." }
    Test-Key $existingVk
    exit 0
}

# ── Main flow ─────────────────────────────────────────────────────────
Ensure-SSOSession

$vk = Get-VirtualKey

if ($KeyOnly) {
    Write-Output $vk
    exit 0
}

Write-Settings $vk
Test-Key $vk

Write-Host ""
Write-Info "Setup complete. You can now use Claude Code."
Write-Info "To re-authenticate later, run this script again."
