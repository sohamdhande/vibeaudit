<div align="center">

# 🛡️ VibeAudit

**Exploit. Patch. Protect.**

Automated BOLA/IDOR vulnerability detection, AI-powered patching, and GitHub PR generation — in one scan.

[![Node.js](https://img.shields.io/badge/Node.js-20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?logo=next.js&logoColor=white)](https://nextjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://docker.com/)
[![AI Powered](https://img.shields.io/badge/AI-Powered-FF6B6B?logo=openai&logoColor=white)](#tech-stack)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

---

## What is VibeAudit?

VibeAudit is an AI-powered authorization security platform that automatically detects BOLA/IDOR vulnerabilities in web applications. It crawls your app as two users, exploits cross-user data access, generates a security patch, and opens a GitHub PR — all in one command. Built for the era of vibe-coded apps where authorization bugs ship faster than they're caught.

---

## The Problem

- **OWASP API Security #1** — Broken Object Level Authorization has been the top API vulnerability for 3 years running. It's the most exploited, least tested class of bug in modern web apps.
- **Vibe-coded apps skip auth logic** — AI-generated and rapidly prototyped applications routinely ship CRUD endpoints without ownership validation. If you can guess the ID, you can steal the data.
- **Manual pen testing doesn't scale** — Traditional security audits take weeks and cost thousands. By the time a report lands, the vulnerable code has already shipped to production.

---

## How It Works

```
One scan. Six stages. Fully automated.
```

1. 🔍 **Crawl** — Puppeteer logs in as the victim user, navigates protected pages, and discovers all parameterized API endpoints via network interception.

2. ⚔️ **Attack** — Replays every discovered request using the attacker's session but the victim's resource IDs. If the attacker gets back the victim's data — it's a confirmed BOLA.

3. 🤖 **Analyze** — AI scores each confirmed finding with CVSS 3.1 severity, confidence level, and identifies sensitive data categories (PII, PHI, financial, auth tokens).

4. 🔧 **Patch** — AI reads the vulnerable route source from GitHub, generates an ownership validation fix, and validates it with Esbuild before committing.

5. 📄 **Report** — Generates an enterprise-grade PDF with a cover page, executive summary, CVSS vector, evidence comparison tables, code diff, and a Playwright regression test.

6. 🚀 **PR** — Opens a GitHub Pull Request with the patched route file and regression test committed, ready for review and merge.

---

## Features

| Feature | Description |
|---|---|
| **Real-time SSE Stream** | Live progress updates for every scan stage, rendered in a terminal-style UI |
| **CVSS 3.1 Scoring** | Automated severity rating with full vector string and confidence score |
| **AI-Generated Patches** | Context-aware ownership validation fixes generated from actual source code |
| **Auto GitHub PR** | One-click PR creation with patched file + Playwright test committed |
| **Enterprise PDF Report** | Professional security assessment with cover page, evidence tables, and diff |
| **Smart URL Deduplication** | Parameterized endpoint grouping to avoid redundant attacks |
| **Playwright Regression Test** | Auto-generated test that verifies the fix returns 403 for unauthorized access |
| **Docker One-Command Setup** | `docker compose up --build` and you're scanning |
| **AI Retry with Backoff** | Exponential backoff with jitter for reliable AI API calls |
| **Dual Auth Support** | Cookie-based and JWT authentication detection and handling |

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | Next.js 16, React 19, Framer Motion, TypeScript, Tailwind CSS |
| **Backend** | Node.js 20, Express, TypeScript |
| **AI** | Groq API (LLM-powered analysis and patch generation) |
| **Crawler** | Puppeteer, Chromium (headless) |
| **Infrastructure** | Docker, Docker Compose |
| **Integrations** | GitHub API (Octokit), Playwright |
| **Validation** | Esbuild (patch syntax verification) |

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- [Groq API Key](https://console.groq.com/) (free tier works)

### Setup

```bash
git clone https://github.com/sohamdhande/vibeaudit
cd vibeaudit
cp .env.example .env
# Add your GROQ_API_KEY to .env
docker compose up --build
# Open http://localhost:3000
```

### Run a Scan

| Field | Value |
|---|---|
| **Target URL** | Your application URL |
| **User A (Victim)** | Account that owns the data |
| **User B (Attacker)** | Account that should NOT have access |
| **GitHub Token** *(optional)* | Personal access token with `repo` scope for automatic PR generation |

Click **"Load ShopVuln Demo"** on the landing page to auto-fill a working demo configuration.

---

## Architecture

```
┌─────────────────┐         ┌──────────────────────────────────────────────┐
│                 │  SSE    │              Express Scanner                │
│   Next.js       │◄───────►│                                              │
│   Frontend      │  POST   │  ┌─────────────────────────────────────┐    │
│                 │────────►│  │  Puppeteer Crawler                  │    │
│  • Terminal UI  │         │  │  Login → Navigate → Intercept APIs  │    │
│  • PDF Report   │         │  └─────────────┬───────────────────────┘    │
│  • Scan History │         │                │                            │
│                 │         │  ┌─────────────▼───────────────────────┐    │
└─────────────────┘         │  │  BOLA Attack Engine                 │    │
                            │  │  Replay requests as attacker        │    │
                            │  └─────────────┬───────────────────────┘    │
                            │                │                            │
                            │  ┌─────────────▼───────────────────────┐    │
                            │  │  AI Analysis (Groq)                 │    │
                            │  │  CVSS scoring + patch generation    │    │
                            │  └─────────────┬───────────────────────┘    │
                            │                │                            │
                            │       ┌────────┴────────┐                   │
                            │       │                 │                   │
                            │  ┌────▼─────┐    ┌──────▼──────┐           │
                            │  │ GitHub   │    │ PDF Report  │           │
                            │  │ PR       │    │ Generator   │           │
                            │  │ (Octokit)│    │ (Puppeteer) │           │
                            │  └──────────┘    └─────────────┘           │
                            └──────────────────────────────────────────────┘
```

---

## Demo Target

[**shopvuln.vercel.app**](https://shopvuln.vercel.app) is an intentionally vulnerable e-commerce application built for testing VibeAudit. It contains a confirmed BOLA vulnerability where any authenticated user can access another user's order data by manipulating resource IDs.

Use the **"Load ShopVuln Demo"** button in the UI to auto-fill credentials and scan configuration.

---

## Project Structure

```
vibeaudit/
├── frontend/          # Next.js 16 application
│   ├── src/
│   │   ├── app/       # App router + API proxy
│   │   ├── components/# UI stages, report sections
│   │   ├── hooks/     # useVibeScanner SSE hook
│   │   └── types/     # Shared TypeScript types
│   └── Dockerfile
├── scanner/           # Express security scanner
│   ├── src/
│   │   ├── server.ts  # Scan orchestration
│   │   ├── attack/    # BOLA detection engine
│   │   ├── ai/        # Groq patch generation
│   │   └── github/    # PR creation (Octokit)
│   └── Dockerfile
├── docker-compose.yml
└── .env.example
```

---

<div align="center">

### Built for [Beyond Tomorrow Summit 2026](https://beyondtomorrow.dev)

**Cybersecurity + AI Track**

*Because the best time to find a BOLA is before your users do.*

</div>