# @spear-secure/api

Language-agnostic HTTP API wrapping `@spear-secure/core`. Use this when the
caller cannot install an npm package (LangChain Python, CrewAI, Flowise, Dify, Go).

## Run

From the repository root:

```bash
docker build -f packages/api/Dockerfile -t sunnypatneedi/spear-api .
docker run -p 7700:7700 \
  -e SPEAR_MODE=enforce \
  -e SPEAR_POLICY=balanced \
  sunnypatneedi/spear-api
```

Or locally after `pnpm --filter @spear-secure/api build`:

```bash
SPEAR_MODE=enforce PORT=7700 node packages/api/dist/index.js
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/pre` | InputGate + InstructionShield |
| POST | `/post` | OutputGate |
| POST | `/session/start` | Create a session |
| POST | `/session/:id/step` | `session.step()` |
| POST | `/session/:id/tools` | `session.tools()` |
| POST | `/session/:id/observe` | `session.observe()` |
| POST | `/session/:id/complete` | `session.complete()` |
| GET | `/health` | Liveness |
| GET | `/metrics` | Session count + telemetry size |

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `PORT` / `SPEAR_API_PORT` | `7700` | Listen port |
| `SPEAR_MODE` | `shadow` | `shadow` or `enforce` |
| `SPEAR_POLICY` | `balanced` | `balanced`, `safe`, or `permissive` |
| `SPEAR_SIDECAR_URL` | unset | Optional Python similarity sidecar |

Python callers should use [`spear-guard`](../python/README.md) rather than raw HTTP.
