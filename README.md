# VibeAudit

> AI-powered dynamic authorization security scanner 
> for modern web applications.

VibeAudit autonomously detects, exploits, and remediates 
Broken Object Level Authorization (BOLA/IDOR) vulnerabilities 
in authenticated web applications.

## How It Works
1. Authenticates into your app as two separate users
2. Crawls protected routes and discovers API endpoints
3. Replays authenticated requests across user sessions
4. Confirms exploitability and classifies sensitive data exposed
5. Generates AI-powered patches and regression tests
6. Opens a GitHub pull request with the fix automatically
7. Generates a detailed, printable PDF security report

## Quick Start

### Prerequisites
- Node.js 18+
- An AI API key (e.g. GROQ_API_KEY)
- Two user accounts on the target application

### Installation
# Clone the repo
git clone https://github.com/your-username/vibeaudit
cd vibeaudit

# Install scanner dependencies
cd scanner && npm install && cd ..

# Install frontend dependencies  
cd frontend && npm install && cd ..

# Configure environment for the Scanner
cp .env.example scanner/.env
# Edit scanner/.env and add your AI API key, GITHUB_TOKEN, and a 32+ char VIBEAUDIT_API_KEY

# Configure environment for the Frontend
echo "SCANNER_API_KEY=your_32_char_key_here" > frontend/.env.local

### Running
# Terminal 1 — Start the scanner
cd scanner && npm run dev

# Terminal 2 — Start the frontend
cd frontend && npm run dev

# Open http://localhost:3000

## Running a Scan
Fill in the scan form:
- Target URL: the app you want to test
- Victim Account: a user who owns data
- Attacker Account: a separate user who should NOT 
  have access to the victim's data
- Click "Launch Security Scan"

## What Gets Detected
VibeAudit detects BOLA/IDOR vulnerabilities where:
- Authenticated users can access resources belonging 
  to other users
- Ownership checks are missing or improperly enforced
- Sensitive data (PII, PHI, financial) is exposed 
  across session boundaries

## Authentication Support
- Session cookies (Auth.js, Express sessions, etc.)
- JWT Bearer tokens
- Auto-detection (recommended)

## Optional: GitHub PR Automation
Add your `GITHUB_TOKEN` (Personal Access Token with `repo` scope) to `scanner/.env`. 
When you run a scan, simply enter the target repository owner and name directly into the VibeAudit web UI to enable automatic PR generation!

## Tech Stack
- Scanner: Node.js, TypeScript, Express, Puppeteer
- Frontend: Next.js, React, TailwindCSS, Framer Motion
- AI Synthesis: LLM-powered patch generation
- AST Validation: Esbuild
- Regression Tests: Playwright (Generated)

## Disclaimer
VibeAudit is designed for authorized security testing only.
Only scan applications you own or have explicit permission 
to test. Unauthorized security testing is illegal.

---

### Known Limitations

- **CSRF token replay**: Cross-session request replay does not model CSRF token flows. Endpoints protected by CSRF tokens may not be accurately tested and could produce false negatives.
- **In-memory scan state**: Currently stored in a Node.js Map. A Redis-backed store is required for horizontal scaling across multiple workers.
- **Browser isolation**: Puppeteer runs in-process. Production hardening requires ephemeral containers (Firecracker/gVisor) per scan.
- **GitHub integration**: Currently PAT-based. A GitHub App OAuth flow is planned for multi-user deployments.