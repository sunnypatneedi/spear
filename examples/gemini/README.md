# Google Gemini + SPEAR Example

Demonstrates SPEAR protection with Google Gemini using the Vercel AI SDK.

## Why Gemini?

- ✅ **Free tier**: 15 requests per minute, 1 million tokens per minute
- ✅ **No credit card required**
- ✅ **Fast**: Gemini Flash is optimized for speed
- ✅ **Good quality**: Comparable to GPT-3.5 Turbo

## Setup

1. **Get a free API key**: https://aistudio.google.com/app/apikey

2. **Create `.env` file**:
   ```bash
   cp .env.example .env
   # Edit .env and add your API key
   ```

3. **Install dependencies**:
   ```bash
   pnpm install
   ```

4. **Run the example**:
   ```bash
   pnpm start
   ```

## What This Example Shows

- ✅ Wrapping a Gemini model with SPEAR
- ✅ Normal queries pass through
- ✅ Prompt injection attacks are blocked
- ✅ Different attack variants (direct exfil, override, reveal)

## Expected Output

```
🎯 SPEAR + Google Gemini Example

Example 1: Normal query (should succeed)

✅ Response: TypeScript is a superset of JavaScript that adds static typing...

---

Example 2: Prompt injection attack (should block)

Response: Request blocked by security policy.

---

Example 3: Another attack variant (should block)

Response: Request blocked by security policy.

✅ Examples complete!
```

## How It Works

```typescript
import { google } from '@ai-sdk/google';
import { wrapLanguageModel } from '@spear/ai-sdk';

// Wrap the model with SPEAR protection
const guardedModel = wrapLanguageModel(
  google('gemini-1.5-flash'),
  {
    policy: 'safe',       // High security
    mode: 'enforce',      // Block attacks
    sessionId: 'demo'     // For telemetry
  }
);

// Use it like any other Vercel AI SDK model
const result = await generateText({
  model: guardedModel,
  prompt: 'Your prompt here'
});
```

## Policies

- **safe**: Strict security (used in this example)
- **balanced**: Moderate security (recommended for most apps)
- **permissive**: Minimal restrictions (development only)

## Modes

- **enforce**: Block detected attacks (production)
- **shadow**: Log attacks but allow through (testing)
- **disabled**: No protection (emergency only)

## Next Steps

- Try different prompts and see what gets blocked
- Change the policy to `balanced` and compare results
- See [../multi-provider](../multi-provider) for OpenAI and Anthropic examples
