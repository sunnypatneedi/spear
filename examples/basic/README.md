# Basic SPEAR Example

Demonstrates core SPEAR API without requiring an LLM.

## What This Example Shows

- ✅ Creating a SPEAR runtime
- ✅ Pre-processing messages (input gate)
- ✅ Post-processing output (output gate)
- ✅ PII detection and masking
- ✅ Telemetry collection

## Run the Example

```bash
pnpm install
pnpm start
```

## Expected Output

```
🎯 SPEAR Basic Example

Example 1: Legitimate message
  Allowed: true
  Messages: 2 messages

Example 2: Prompt injection attack
  Allowed: false
  Reason: direct_exfil
  Refusal: I cannot help with that request.

Example 3: PII detection in output
  Allowed: true
  Original: Contact me at john@example.com or call 555-123-4567
  Sanitized: Contact me at [EMAIL_REDACTED] or call [PHONE_REDACTED]

Example 4: Telemetry data
  Total events: 3
  Blocked requests: 1
  Attack types detected: [ 'direct_exfil' ]

✅ Examples complete!
```

## Next Steps

- See [../edge-function](../edge-function) for Supabase Edge Function deployment
- See the full [README](../../README.md) for Session API and provenance tracking
