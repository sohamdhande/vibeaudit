# VibeAudit Scanner

Backend scanner service running on port 4000.

## API

### POST /scan
Starts a security scan. Returns Server-Sent Events stream.
Requires Header: `X-API-Key`

Request body:
{
  "targetUrl": "https://your-app.com",        // required
  "userA": {                                   // required
    "email": "victim@app.com",
    "password": "password123"
  },
  "userB": {                                   // required
    "email": "attacker@app.com", 
    "password": "password123"
  },
  "loginPath": "/login",                       // optional
  "pagesToCrawl": ["/dashboard", "/orders"],   // optional
  "authType": "auto",                          // optional
  "loginFieldSelectors": {                     // optional
    "email": "input[name=email]",
    "password": "input[name=password]",
    "submit": "button[type=submit]"
  }
}

### GET /scan/:scanId/stream
Reconnects to an active scan's Server-Sent Events stream.
Requires Header: `X-API-Key`

### GET /health
Returns scanner health and uptime.

## Environment Variables
See root .env.example for configuration.
