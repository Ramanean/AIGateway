"""
Bifrost VK Broker — AWS Lambda Function URL (IAM auth).

AWS validates the caller's identity via SigV4 before this code runs.
This function only does one thing: look up the caller's virtual key in Bifrost.

Environment variables:
  BIFROST_URL          — e.g. https://bifrost.mycompany.com
  BIFROST_MGMT_TOKEN   — management bearer token for the Bifrost API
"""

import json
import os
import urllib.request
import urllib.parse
import urllib.error


BIFROST_URL = os.environ["BIFROST_URL"].rstrip("/")
BIFROST_MGMT_TOKEN = os.environ["BIFROST_MGMT_TOKEN"]


def lambda_handler(event, context):
    iam = event.get("requestContext", {}).get("authorizer", {}).get("iam", {})
    caller_arn = iam.get("userArn", "")

    # Identity Center assumed-role ARNs look like:
    #   arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_PermSetName_abc123/jane.doe@mycompany.com
    # The last segment after "/" is the session name, which Identity Center
    # sets to the user's email (or username — depends on your attribute mapping).
    parts = caller_arn.rsplit("/", 1)
    if len(parts) < 2 or "@" not in parts[1]:
        return _err(403, "Could not extract email from caller ARN. "
                         "Check your Identity Center attribute mapping.")

    email = parts[1]

    encoded_email = urllib.parse.quote(email, safe="")
    url = f"{BIFROST_URL}/api/users/email/{encoded_email}/virtual-keys"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {BIFROST_MGMT_TOKEN}",
    })

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return _err(404, f"No Bifrost user found for {email}")
        return _err(502, f"Bifrost returned {e.code}")
    except Exception as e:
        return _err(502, f"Bifrost request failed: {e}")

    active_keys = [k for k in data.get("virtual_keys", []) if k.get("is_active")]
    if not active_keys:
        return _err(404, f"No active virtual key for {email}")

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "email": email,
            "virtual_key": active_keys[0]["value"],
        }),
    }


def _err(code, msg):
    return {
        "statusCode": code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": msg}),
    }
