# PF-4 Real LLM Docker Lab

Validates the full physarum-maze evidence pipeline with a real LLM endpoint:

```
DiscoveryQuery (ports: [80, 8080, 7777])
  → OpenAiCompatibleClient.query()      # real LLM call
  → PropagationStrategy { Http { path:"/", port:7777 } }
  → PolicyGate.evaluate() → Accepted
  → HttpGet { path:"/", port:7777 } → http://172.20.0.5:7777/ → 200 OK
  → LlmAttemptEvidence in lineage
```

## Prerequisites

- Docker Desktop with cloud builder `cloud-expertsonline-physarum-attack-paths`
- An OpenAI-compatible LLM endpoint and API key

## Setup

```bash
cd examples/pf-4-real-llm-lab/sensitive-info
cp .env.example .env.local
# edit .env.local — fill in PHYSARUM_LLM_ENDPOINT and LLM_API_KEY
source .env.local
```

## Run

```bash
source examples/pf-4-real-llm-lab/sensitive-info/.env.local
./Utilities/docker-lab.sh
```

## Validation criteria (PF-4)

1. `DiscoveryQuery` is built from real `SensingResult` + `PatternFindingSummary`
2. Real LLM endpoint receives the structured context
3. LLM returns a valid `PropagationStrategy` matching the schema
4. `PolicyGate` accepts or rejects deterministically
5. `LlmAttemptEvidence` records request / decision / result in lineage
6. Non-standard ports are preserved in the strategy or rejected if absent
7. No AWS — controlled Docker lab only

## Credentials

API keys and endpoint URLs live in `sensitive-info/` — see that directory's README.
