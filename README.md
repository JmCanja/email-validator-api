# Email Validator API

A lightweight Node.js/Express backend that validates email addresses using:

1. **Format check** — RFC 5322 syntax validation
2. **MX record lookup** — real DNS query to confirm the domain accepts mail
3. **SMTP probe** — connects to the mail server and attempts RCPT TO verification
4. **Heuristics** — disposable provider detection, role-address flagging, typo detection

---

## Quick start

```bash
npm install
npm start
# API running at http://localhost:3000
```

Dev mode (auto-restart):
```bash
npm run dev
```

With Docker:
```bash
docker build -t email-validator-api .
docker run -p 3000:3000 email-validator-api
```

---

## Endpoints

### `GET /health`
Health check.

**Response:**
```json
{ "status": "ok", "version": "1.0.0", "timestamp": "2024-01-01T00:00:00.000Z" }
```

---

### `POST /api/validate` — Single email

**Request body:**
```json
{
  "email": "user@example.com",
  "smtp_check": true,
  "debug": false
}
```

| Field        | Type    | Default | Description                          |
|--------------|---------|---------|--------------------------------------|
| `email`      | string  | —       | Email address to validate (required) |
| `smtp_check` | boolean | `true`  | Whether to perform SMTP verification |
| `debug`      | boolean | `false` | Include raw SMTP conversation log    |

**Response:**
```json
{
  "email": "user@example.com",
  "checks": {
    "format": { "pass": true, "detail": "Passed all syntax checks" },
    "mx": {
      "pass": true,
      "detail": "2 MX record(s) found",
      "records": [
        { "exchange": "mail.example.com", "priority": 10 }
      ]
    },
    "smtp": {
      "pass": true,
      "detail": "Mailbox accepted by mail.example.com",
      "smtpCode": 250
    }
  },
  "flags": [],
  "score": 100,
  "status": "valid",
  "deliverable": true,
  "reason": "Mailbox verified and accepting mail",
  "duration_ms": 420
}
```

**Status values:**

| Status    | Meaning                                          |
|-----------|--------------------------------------------------|
| `valid`   | All checks passed                                |
| `invalid` | Format invalid, no MX, or mailbox rejected       |
| `risky`   | Deliverable but disposable/suspicious            |
| `unknown` | MX exists, SMTP inconclusive (greylisting, etc.) |

**Score (0–100):**
- Format: +30
- MX found: +35
- SMTP verified: +35 (inconclusive: +15)
- Disposable: −20
- Typo detected: −10

---

### `GET /api/validate?email=` — Single email (GET)

```
GET /api/validate?email=user@example.com&smtp_check=true&debug=false
```

Same response as POST.

---

### `POST /api/validate/bulk` — Bulk validation (up to 100)

**Request body:**
```json
{
  "emails": [
    "alice@example.com",
    "bob@invalid-domain-xyz.io",
    "fake@mailinator.com"
  ],
  "smtp_check": true
}
```

**Response:**
```json
{
  "summary": {
    "total": 3,
    "valid": 1,
    "invalid": 1,
    "risky": 1,
    "unknown": 0
  },
  "results": [ ...same format as single validate... ]
}
```

**Limits:**
- Max 100 emails per request
- Rate limited to 10 bulk requests/min per IP

---

## Rate limits

| Endpoint       | Limit             |
|----------------|-------------------|
| All `/api/`    | 60 requests/min   |
| `/api/validate/bulk` | 10 requests/min |

---

## Flags

Each result may include a `flags` array:

```json
"flags": [
  { "type": "disposable", "message": "Disposable/temporary email provider" },
  { "type": "role",       "message": "Role-based address (admin)" },
  { "type": "typo",       "message": "Possible domain typo: \"gmial.com\" → did you mean \"gmail.com\"?" }
]
```

---

## Notes on SMTP verification

- SMTP checks connect to port 25 of the target mail server. Many residential ISPs and cloud providers (AWS, GCP, Render free tier) **block outbound port 25**. Use a VPS or dedicated server for reliable SMTP probes.
- Some mail servers use **catch-all** configurations that accept all RCPT TO addresses regardless — these will return `deliverable: true` even for non-existent mailboxes.
- Some servers use **greylisting** and temporarily reject unknown senders — these return `status: unknown`.
- SMTP timeout is 8 seconds per check.

---

## Deploy options

| Platform        | Notes                                                    |
|-----------------|----------------------------------------------------------|
| VPS (DigitalOcean, Hetzner, Vultr) | Best — port 25 usually open      |
| Railway / Fly.io | Port 25 may be restricted; use `smtp_check: false`     |
| Docker          | `docker build -t email-validator . && docker run -p 3000:3000 email-validator` |
| PM2             | `pm2 start server.js --name email-validator`            |
