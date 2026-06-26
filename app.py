import re
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# ─────────────────────────────────────────────
#  Credential patterns
# ─────────────────────────────────────────────
PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "category": "Cloud",
        "regex": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
        "replacement": "AWS_ACCESS_KEY_REDACTED",
    },
    {
        "name": "AWS Secret Access Key",
        "category": "Cloud",
        "regex": r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "replacement": "AWS_SECRET_KEY_REDACTED",
    },
    {
        "name": "Google API Key",
        "category": "Cloud",
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "replacement": "GOOGLE_API_KEY_REDACTED",
    },
    {
        "name": "GitHub Token",
        "category": "VCS",
        "regex": r"gh[pousr]_[A-Za-z0-9]{36,255}",
        "replacement": "GITHUB_TOKEN_REDACTED",
    },
    {
        "name": "Generic API Key Assignment",
        "category": "Generic",
        "regex": r"(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9\-_]{16,64})['\"]",
        "replacement": "API_KEY_REDACTED",
    },
    {
        "name": "Generic Secret Assignment",
        "category": "Generic",
        "regex": r"(?i)(?:secret|client_secret|app_secret)\s*[:=]\s*['\"]([A-Za-z0-9\-_!@#$%^&*]{8,64})['\"]",
        "replacement": "SECRET_REDACTED",
    },
    {
        "name": "Generic Password Assignment",
        "category": "Generic",
        "regex": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,64})['\"]",
        "replacement": "PASSWORD_REDACTED",
    },
    {
        "name": "Private Key Block",
        "category": "Cryptographic",
        "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "replacement": "PRIVATE_KEY_REDACTED",
    },
    {
        "name": "Slack Token",
        "category": "SaaS",
        "regex": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
        "replacement": "SLACK_TOKEN_REDACTED",
    },
    {
        "name": "Stripe Secret Key",
        "category": "Payments",
        "regex": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
        "replacement": "STRIPE_KEY_REDACTED",
    },
    {
        "name": "Twilio Auth Token",
        "category": "SaaS",
        "regex": r"(?i)twilio.*?['\"]([a-f0-9]{32})['\"]",
        "replacement": "TWILIO_TOKEN_REDACTED",
    },
    {
        "name": "Bearer Token in Header",
        "category": "Auth",
        "regex": r"(?i)authorization\s*:\s*bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)",
        "replacement": "BEARER_TOKEN_REDACTED",
    },
    {
        "name": "Connection String with Password",
        "category": "Database",
        "regex": r"(?i)(?:mongodb|mysql|postgres|postgresql|redis|amqp|jdbc)(?:\+\w+)?://[^:]+:([^@\s'\"]{4,}?)@",
        "replacement": "DB_PASSWORD_REDACTED",
    },
]


def scan_and_strip(text: str):
    """
    Scans text for credential patterns.
    Returns a list of findings and the cleaned (redacted) text.
    """
    findings = []
    cleaned = text

    for pattern in PATTERNS:
        compiled = re.compile(pattern["regex"])
        matches = compiled.findall(cleaned)

        if matches:
            # Count unique match strings
            unique = list(dict.fromkeys(
                m if isinstance(m, str) else m[0] for m in matches
            ))
            findings.append({
                "name": pattern["name"],
                "category": pattern["category"],
                "count": len(matches),
                "samples": [u[:6] + "…" for u in unique[:3]],  # partial preview only
            })
            cleaned = compiled.sub(pattern["replacement"], cleaned)

    return findings, cleaned


# ─────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    text = data.get("text", "")

    if not text.strip():
        return jsonify({"error": "No text provided."}), 400

    findings, cleaned = scan_and_strip(text)
    return jsonify({
        "findings": findings,
        "cleaned": cleaned,
        "total_issues": sum(f["count"] for f in findings),
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
