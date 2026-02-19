# @spear-secure/supabase

SPEAR adapter for Supabase Edge Functions (Deno runtime).

## Installation

```bash
# In your Supabase project
import { guardLLMCall } from 'https://esm.sh/@spear-secure/supabase@1.0.0'
```

## Usage

```typescript
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { guardLLMCall } from '@spear-secure/supabase'

serve(async (req) => {
  const { messages } = await req.json()

  const result = await guardLLMCall(messages, {
    policy: 'balanced',
    mode: 'enforce'
  })

  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json' }
  })
})
```

## Documentation

See the [main SPEAR documentation](https://github.com/sunnypatneedi/spear) for more details.

## License

Apache-2.0
