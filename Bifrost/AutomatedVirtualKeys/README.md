# Bifrost + AWS SSO Broker (Architecture B)

Route Claude Code through Bifrost using AWS SSO for authentication.
No custom auth code — AWS validates identity, Lambda fetches the virtual key.

## Prerequisites

- AWS account with IAM Identity Center enabled
- Okta federated to Identity Center (SAML or OIDC)
- Bifrost AI Gateway deployed with a management token
- AWS CLI v2, Python 3.9+, boto3 installed on developer machines

## Architecture

```
Developer laptop                         AWS                              Bifrost
─────────────────                  ─────────────────                  ──────────────
aws sso login ──────────────> Identity Center ──> Okta
       │                          (federation)
       │ SigV4-signed request
       ▼
Lambda Function URL ◄── IAM auth validates caller
       │
       │ "Who is calling?" → jane.doe@mycompany.com (from ARN)
       │
       │ GET /api/users/email/jane.doe@.../virtual-keys
       ▼
  Returns virtual key ◄──────────────────────────────────── Bifrost API
       │
       ▼
settings.json updated
Claude Code → Bifrost → Anthropic
```

## Step 1: Identity Center Attribute Mapping

Ensure Okta maps the user's **email** as the Identity Center username.
This becomes the assumed-role session name, which the Lambda reads.

In Identity Center → Settings → Identity source → Attribute mapping:
- `email` → `${user:email}` (from Okta)

## Step 2: Create a Permission Set

Create a permission set that grants `lambda:InvokeFunctionUrl` on the broker:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunctionUrl",
            "Resource": "arn:aws:lambda:us-east-1:ACCOUNT_ID:function:bifrost-vk-broker"
        }
    ]
}
```

Assign this permission set to the relevant Identity Center groups.

## Step 3: Configure an AWS CLI SSO Profile

Each developer adds this to `~/.aws/config`:

```ini
[profile bifrost]
sso_session     = mycompany
sso_account_id  = 123456789012
sso_role_name   = BifrostDeveloperAccess
region          = us-east-1

[sso-session mycompany]
sso_start_url   = https://mycompany.awsapps.com/start
sso_region      = us-east-1
sso_registration_scopes = sso:account:access
```

## Step 4: Deploy the Lambda

```bash
BIFROST_URL=https://bifrost.mycompany.com \
BIFROST_MGMT_TOKEN=sk-mgmt-xxxxx \
LAMBDA_ROLE_ARN=arn:aws:iam::123456789012:role/bifrost-broker-role \
bash lambda/deploy.sh
```

Note the Function URL printed at the end.

## Step 5: Run the Client Script

### macOS / Linux
```bash
BROKER_URL=https://abc123.lambda-url.us-east-1.on.aws/ \
BIFROST_URL=https://bifrost.mycompany.com \
bash client/bifrost-auth.sh
```

### Windows (PowerShell)
```powershell
$env:BROKER_URL = "https://abc123.lambda-url.us-east-1.on.aws/"
$env:BIFROST_URL = "https://bifrost.mycompany.com"
.\client\bifrost-auth.ps1
```

## Step 6 (Optional): Auto-Refresh with apiKeyHelper

Instead of a static key, configure Claude Code to call the script on every request:

**settings.json** (`~/.claude/settings.json` or `%USERPROFILE%\.claude\settings.json`):
```json
{
    "apiKeyHelper": "bash /path/to/bifrost-auth.sh --key-only",
    "env": {
        "ANTHROPIC_BASE_URL": "https://bifrost.mycompany.com/anthropic",
        "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "3600000",
        "SSO_PROFILE": "bifrost",
        "BROKER_URL": "https://abc123.lambda-url.us-east-1.on.aws/"
    }
}
```

On Windows, use the PowerShell variant:
```json
{
    "apiKeyHelper": "powershell -File C:\\path\\to\\bifrost-auth.ps1 -KeyOnly",
    "env": {
        "ANTHROPIC_BASE_URL": "https://bifrost.mycompany.com/anthropic",
        "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "3600000",
        "SSO_PROFILE": "bifrost",
        "BROKER_URL": "https://abc123.lambda-url.us-east-1.on.aws/"
    }
}
```

The TTL of 1 hour means Claude Code caches the key and only re-invokes
the helper when it expires. The 8-hour SSO session covers a full workday.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Could not extract email from caller ARN" | Identity Center maps username, not email | Fix attribute mapping in Step 1 |
| "SSO session expired" in --key-only mode | SSO session timed out (8h default) | Run `aws sso login --profile bifrost` |
| "No Bifrost user found" | User exists in Okta/AWS but not provisioned in Bifrost | Check Bifrost SCIM sync or manually create the user |
| "No active virtual key" | Access Profile hasn't generated a key yet | Verify the Access Profile is attached with `is_default: true` |
| Lambda returns 403 | Missing `lambda:InvokeFunctionUrl` permission | Update the permission set in Step 2 |
