# SAPPS Sidecar

Optional ML service for cross-lingual similarity detection.

## Quick Start

```bash
# Build
docker build -t spear-sidecar .

# Run
docker run -p 8088:8088 spear-sidecar

# Configure SAPPS to use it
export SPEAR_SIDECAR_URL=http://localhost:8088
```

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
