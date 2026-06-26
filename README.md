# SecureCommit 🛡️

A local Flask tool that scans code/config text for hardcoded credentials and strips them out via regex.

---

## Setup & Run (3 steps)

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the server

```bash
python app.py
```

You'll see:
```
 * Running on http://127.0.0.1:5000
```

### 3. Open the app

Visit **http://localhost:5000** in your browser.

---

## What it detects

| Pattern                      | Category    | Example match                    |
|------------------------------|-------------|----------------------------------|
| AWS Access Key ID            | Cloud       | `AKIAIOSFODNN7EXAMPLE`          |
| AWS Secret Access Key        | Cloud       | `aws_secret_key = "..."`        |
| Google API Key               | Cloud       | `AIzaSy...`                     |
| GitHub Token                 | VCS         | `ghp_...` / `gho_...`          |
| Generic API Key assignment   | Generic     | `api_key = "abc123..."`         |
| Generic Secret assignment    | Generic     | `secret = "mysecret"`           |
| Generic Password assignment  | Generic     | `password = "hunter2"`          |
| Private Key Block (PEM)      | Cryptographic | `-----BEGIN RSA PRIVATE KEY--`|
| Slack Token                  | SaaS        | `xoxb-...`                     |
| Stripe Secret Key            | Payments    | `sk_live_...`                   |
| Twilio Auth Token            | SaaS        | 32-char hex after "twilio"      |
| Bearer Token in Header       | Auth        | `Authorization: Bearer eyJ...`  |
| DB Connection String         | Database    | `postgres://user:pass@host`     |

---

## Project structure

```
securecommit/
├── app.py              # Flask backend + all regex patterns
├── requirements.txt
├── README.md
└── templates/
    └── index.html      # Single-page frontend
```

---

## Tips

- Press **Ctrl+Enter** (or **Cmd+Enter**) in the input box to trigger a scan.
- The redacted output replaces each secret with a named placeholder (e.g. `AWS_ACCESS_KEY_REDACTED`), making it safe to commit.
- Add more patterns in `app.py` → `PATTERNS` list — each entry just needs a `name`, `category`, `regex`, and `replacement`.
