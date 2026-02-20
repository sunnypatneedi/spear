# Supabase Edge Function + SPEAR Example

Demonstrates deploying SPEAR protection as a Supabase Edge Function (Deno runtime).

## Why Edge Functions?

- ✅ **Serverless**: No infrastructure to manage
- ✅ **Global**: Deploy to 30+ regions
- ✅ **Secure**: Runs in isolated Deno runtime
- ✅ **Fast**: Sub-100ms cold starts

## Setup

### 1. Install Supabase CLI

```bash
brew install supabase/tap/supabase
# or
npm install -g supabase
```

### 2. Initialize Supabase Project

```bash
supabase init
```

### 3. Create Edge Function

```bash
supabase functions new protected-llm-call
```

### 4. Copy This Example

Copy the contents of `index.ts` to your new function:

```bash
cp examples/edge-function/index.ts supabase/functions/protected-llm-call/index.ts
```

### 5. Deploy

```bash
supabase functions deploy protected-llm-call
```

## Using @spear-secure/core

In your edge function, import and use the SPEAR core library:

```typescript
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { quick } from 'https://esm.sh/@spear-secure/core';

const spear = quick('balanced', { mode: 'enforce' });

serve(async (req) => {
  const { messages } = await req.json();

  // SPEAR guards the input
  const pre = await spear.pre(messages);

  if (!pre.allowed) {
    return new Response(
      JSON.stringify({ error: pre.reason }),
      { status: 400 }
    );
  }

  // Call your LLM here with pre.messages
  // const llmResponse = await callLLM(pre.messages);

  // SPEAR guards the output
  // const post = await spear.post({ output: llmResponse, canary: pre.canary });

  return new Response(JSON.stringify({ success: true }));
});
```

## Call From Client

```typescript
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const { data, error } = await supabase.functions.invoke('protected-llm-call', {
  body: {
    messages: [
      { role: 'system', content: 'You are a helpful assistant.' },
      { role: 'user', content: 'What is TypeScript?' }
    ]
  }
});
```

## Architecture

```
Client → Supabase Edge Function → SPEAR → LLM → SPEAR → Client
         (Deno Runtime)           (Guards)     (API)   (Sanitize)
```

## Benefits

1. **Centralized Security**: All LLM calls go through SPEAR
2. **Rate Limiting**: Supabase provides built-in rate limiting
3. **Auth Integration**: Automatic user authentication
4. **Low Latency**: Edge deployment near users
5. **Cost Effective**: Pay per invocation

## Environment Variables

Set these in your Supabase project dashboard:

```bash
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SPEAR_MODE=enforce  # or shadow, disabled
SPEAR_POLICY=balanced  # or safe, permissive
```

## Testing Locally

```bash
supabase start
supabase functions serve protected-llm-call

# In another terminal
curl -i --location --request POST \
  'http://localhost:54321/functions/v1/protected-llm-call' \
  --header 'Authorization: Bearer YOUR_ANON_KEY' \
  --header 'Content-Type: application/json' \
  --data '{"messages":[{"role":"user","content":"Hello"}]}'
```

## Deployment Checklist

- [ ] Install Supabase CLI
- [ ] Link to Supabase project: `supabase link`
- [ ] Create edge function
- [ ] Add SPEAR import
- [ ] Set environment variables
- [ ] Deploy: `supabase functions deploy`
- [ ] Test with curl or client
- [ ] Monitor in Supabase dashboard

## Next Steps

- Add LLM integration (OpenAI, Gemini, etc.)
- Implement response caching
- Add telemetry logging to Supabase
- Set up monitoring and alerts
