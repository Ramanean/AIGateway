#!/usr/bin/env bash
# bifrost-auth.sh — Client-side helper for Claude Code + Bifrost via AWS SSO.
#
# What it does:
#   1. Ensures you have a valid AWS SSO session (opens browser if expired)
#   2. Calls the Lambda broker (signed with your SSO credentials)
#   3. Writes the virtual key into Claude Code's settings.json
#   4. Verifies the key works with a lightweight API call
#
# Configuration (edit these or set as environment variables):
#   SSO_PROFILE   — AWS CLI profile name configured for Identity Center
#   BROKER_URL    — Lambda Function URL from the deploy step
#   BIFROST_URL   — Your Bifrost gateway base URL
#
# Usage:
#   bash bifrost-auth.sh              # interactive — opens browser for SSO
#   bash bifrost-auth.sh --check      # just check if current key is valid
#
# To use as Claude Code's apiKeyHelper (re-authenticates automatically):
#   Set in settings.json:
#     "apiKeyHelper": "bash /path/to/bifrost-auth.sh --key-only"

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────
SSO_PROFILE="${SSO_PROFILE:-bifrost}"
BROKER_URL="${BROKER_URL:-https://CHANGEME.lambda-url.us-east-1.on.aws/}"
BIFROST_URL="${BIFROST_URL:-https://bifrost.mycompany.com}"
SETTINGS_FILE="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
# ───────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# ── Parse flags ────────────────────────────────────────────────────────
KEY_ONLY=false
CHECK_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --key-only)  KEY_ONLY=true ;;
        --check)     CHECK_ONLY=true ;;
    esac
done

# ── Dependency check ──────────────────────────────────────────────────
for cmd in aws jq curl; do
    command -v "$cmd" >/dev/null || fail "'$cmd' is required but not found."
done

# ── Step 1: Ensure valid AWS SSO session ──────────────────────────────
ensure_sso_session() {
    if aws sts get-caller-identity --profile "$SSO_PROFILE" &>/dev/null; then
        $KEY_ONLY || info "AWS SSO session is active."
        return 0
    fi

    if $KEY_ONLY; then
        # apiKeyHelper mode — can't open a browser interactively
        echo "ERROR: SSO session expired. Run 'aws sso login --profile $SSO_PROFILE' first." >&2
        exit 1
    fi

    warn "SSO session expired or missing. Opening browser for sign-in..."
    aws sso login --profile "$SSO_PROFILE"

    aws sts get-caller-identity --profile "$SSO_PROFILE" &>/dev/null \
        || fail "SSO login did not succeed."
    info "SSO login successful."
}

# ── Step 2: Call the Lambda broker ────────────────────────────────────
fetch_virtual_key() {
    $KEY_ONLY || info "Requesting virtual key from broker..."

    # aws curl signs the request with SigV4 using your SSO credentials
    response=$(aws lambda invoke-with-response-stream \
        --function-name "" \
        --profile "$SSO_PROFILE" \
        --region "" \
        --payload '{}' \
        /dev/null 2>&1 || true)

    # Simpler approach: use curl with SigV4 signing via aws-sigv4
    response=$(curl -s -w "\n%{http_code}" \
        --aws-sigv4 "aws:amz:${AWS_REGION:-us-east-1}:lambda" \
        --user "$(aws configure get aws_access_key_id --profile "$SSO_PROFILE"):$(aws configure get aws_secret_access_key --profile "$SSO_PROFILE")" \
        -H "x-amz-security-token: $(aws configure get aws_session_token --profile "$SSO_PROFILE")" \
        "$BROKER_URL" 2>/dev/null || true)

    # If curl --aws-sigv4 isn't available, fall back to a Python one-liner
    if [ -z "$response" ] || echo "$response" | tail -1 | grep -qv '^2'; then
        response=$(python3 - "$BROKER_URL" "$SSO_PROFILE" <<'PYEOF'
import sys, json, boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import urllib.request

url, profile = sys.argv[1], sys.argv[2]
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
PYEOF
        )
    fi

    if [ -z "$response" ]; then
        fail "No response from broker at $BROKER_URL"
    fi

    # Extract virtual key from response
    vk=$(echo "$response" | jq -r '.virtual_key // empty' 2>/dev/null)
    email=$(echo "$response" | jq -r '.email // "unknown"' 2>/dev/null)

    if [ -z "$vk" ]; then
        error_msg=$(echo "$response" | jq -r '.error // empty' 2>/dev/null)
        fail "Broker error: ${error_msg:-unexpected response format}"
    fi

    $KEY_ONLY || info "Got virtual key for $email"
    echo "$vk"
}

# ── Step 3: Write to Claude Code settings ─────────────────────────────
write_settings() {
    local vk="$1"

    mkdir -p "$(dirname "$SETTINGS_FILE")"

    if [ ! -f "$SETTINGS_FILE" ]; then
        echo '{}' > "$SETTINGS_FILE"
    fi

    jq --arg url "$BIFROST_URL/anthropic" \
       --arg vk "$vk" \
       '.env = ((.env // {}) + {ANTHROPIC_BASE_URL: $url, ANTHROPIC_AUTH_TOKEN: $vk})' \
       "$SETTINGS_FILE" > "${SETTINGS_FILE}.tmp" \
       && mv "${SETTINGS_FILE}.tmp" "$SETTINGS_FILE"

    info "Updated $SETTINGS_FILE"
}

# ── Step 4: Verify the key works ──────────────────────────────────────
verify_key() {
    local vk="$1"
    info "Verifying key against Bifrost..."

    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "x-api-key: $vk" \
        -H "Content-Type: application/json" \
        -d '{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}' \
        "$BIFROST_URL/anthropic/v1/messages" 2>/dev/null || echo "000")

    case "$status" in
        200) info "Key is valid. Claude Code is now routed through Bifrost." ;;
        401) fail "Key was rejected (401). It may have been revoked." ;;
        429) info "Key is valid (rate-limited, which confirms auth works)." ;;
        000) warn "Could not reach Bifrost to verify. Key has been saved — it may work." ;;
        *)   warn "Bifrost returned HTTP $status. Key saved but may not be valid." ;;
    esac
}

# ── Check mode ────────────────────────────────────────────────────────
if $CHECK_ONLY; then
    if [ ! -f "$SETTINGS_FILE" ]; then
        fail "No settings file at $SETTINGS_FILE"
    fi
    existing_vk=$(jq -r '.env.ANTHROPIC_AUTH_TOKEN // empty' "$SETTINGS_FILE" 2>/dev/null)
    if [ -z "$existing_vk" ]; then
        fail "No ANTHROPIC_AUTH_TOKEN in settings."
    fi
    verify_key "$existing_vk"
    exit 0
fi

# ── Main flow ─────────────────────────────────────────────────────────
ensure_sso_session

vk=$(fetch_virtual_key)

if $KEY_ONLY; then
    # apiKeyHelper mode: just print the key to stdout, no file writes
    echo "$vk"
    exit 0
fi

write_settings "$vk"
verify_key "$vk"

echo ""
info "Setup complete. You can now use Claude Code."
info "To re-authenticate later, run this script again."
info "To use as auto-refresh: set apiKeyHelper in settings.json to:"
echo "    \"apiKeyHelper\": \"bash $(realpath "$0") --key-only\""
