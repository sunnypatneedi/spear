# SPEAR Sidecar

Optional ML service for cross-lingual similarity detection.

## Quick Start

```bash
# Build
docker build -t spear-sidecar .

# Run
docker run -p 8088:8088 \
  -e SPEAR_SYSTEM_TEXT="your system prompt" \
  -e SPEAR_SIDECAR_KEY="replace-with-a-long-random-secret" \
  spear-sidecar

# Configure SPEAR to use it
export SPEAR_SIDECAR_URL=http://localhost:8088
export SPEAR_SIDECAR_KEY=replace-with-a-long-random-secret
```

`SPEAR_SIDECAR_KEY` authenticates `POST /v1/similarity`. Without it, any process that can reach the sidecar can oracle-query the cached system-prompt embedding. Always set it in production.

## API

**POST /v1/similarity**
```json
{
  "text": "Output to check",
  "reference": "System prompt to compare against"
}
```

Returns:
```json
{
  "score": 0.85
}
```
