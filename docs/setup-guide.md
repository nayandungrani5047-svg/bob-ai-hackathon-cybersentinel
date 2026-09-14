# Setup Guide

## Prerequisites

Before running CyberSentinel, install:

- Python 3.10 or later
- Node.js LTS
- Git

## 1. Clone the Repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd bob-ai-hackathon-cybersentinel

## 2. Backend Setup

```bash
cd src/backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
Backend : http://127.0.0.1.:8000
API Documentation : http://127.0.0.1.:8000/docs

## 3. Frontend Setup

```bash
cd src/frontend
npm.cmd install
npm.cmd run dev
frontend : http://localhost:5173

### 4. Environment Variables

```markdown

The current hackathon MVP does not require production credentials or external API keys.

If environment-specific configuration is required in the future, use `.env.example` as the reference.

Do not commit real `.env` files or credentials to the repository.

## 5. Verification

After starting both services:

1. Open the frontend.
2. Confirm that the Dashboard loads.
3. Open the Alerts page.
4. Click **Ingest Alerts**.
5. Verify that alerts are processed.
6. Open the Incidents page.
7. Open an incident and verify its investigation details.
8. Check prioritisation, MITRE ATT&CK mapping, and BLUF information.

## 6. Troubleshooting

### Python command not found

```bash
python --version
cd src/backend python -m pip install -r requirments.txt
node --version
npm.cmd install
npm.cmd run dev
 API : http://127.0.0.1.:8000/docs
 Running backend :http://127.0.0.1.:8000

 ## 7. Running the complete Application
 Backend : cd src/backend python -m uvicorn main:app --reload
 frontend : cd src/frontend npm.cmd run dev
