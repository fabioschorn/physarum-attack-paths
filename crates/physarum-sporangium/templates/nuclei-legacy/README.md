# nuclei-legacy — Upstream Template Library

This directory contains a full copy of [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates), imported 2026-06-02 as part of PR #133 (physarum-sporangium Nuclei port).

**13,264 templates** — baked into the `physarum-maze:lab` Docker image at `/templates/nuclei-legacy`.

## Usage in physarum-maze

The YAML loader reads from `PHYSARUM_TEMPLATE_DIR` (default: `/templates/nuclei-legacy` in Docker).

Filter via environment variables:
```env
PHYSARUM_TEMPLATE_TAGS=rce,cve          # comma-separated tags
PHYSARUM_TEMPLATE_SEVERITY=critical,high # comma-separated severities
PHYSARUM_TEMPLATE_IDS=CVE-2021-23017    # specific template IDs (bypasses other filters)
```

## Full Documentation

See [General-Docs/SPORANGIUM_TEMPLATE_CATALOG_AND_LLM_INTEGRATION.md](../../../../General-Docs/SPORANGIUM_TEMPLATE_CATALOG_AND_LLM_INTEGRATION.md) for:
- Template loading architecture
- LLM integration model
- Advisory cache relationship
- Filter strategy per lab type
- Future template development

## Retained Reference Files

| File | Purpose |
|------|---------|
| `LICENSE.md` | MIT license from upstream |
| `TEMPLATE-CREATION-GUIDE.md` | Guide for writing new detection templates |
| `TEMPLATE-REVIEW-GUIDE.md` | Quality review criteria |
| `TEMPLATES-STATS.md` | Full tag/severity/directory statistics |
| `TOP-10.md` | Top-10 statistics summary |
