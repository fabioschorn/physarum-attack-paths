# sensitive-info

This directory holds **local-only** credential files for the PF-4 Docker Lab.

Files in this directory (except `.env.example`, this `README.md`, and `.gitkeep`)
are excluded from version control by `.gitignore`. Never commit real API keys,
tokens, or secrets here.

## Quick start

```bash
cp .env.example .env.local
# fill in PHYSARUM_LLM_ENDPOINT and LLM_API_KEY in .env.local
source .env.local
../../../../Utilities/docker-lab.sh
```

## What stays local

| Pattern | Purpose |
|---|---|
| `.env.local` | Your real LLM endpoint + API key |
| `*.vars` | Alternative variable files |
| `*.local` | Any `*.local`-suffixed config |

`.env.example` is the only committed file here — it is a blank template with no secrets.
