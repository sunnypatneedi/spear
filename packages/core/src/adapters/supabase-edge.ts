/**
 * SPEAR Adapter for Supabase Edge Functions (Deno Runtime)
 * 
 * Provides drop-in security for edge functions that call LLMs.
 * Compatible with Deno runtime constraints (no Node.js APIs).
 * 
 * Note: This module uses dynamic imports to work in both Node and Deno.
 */

/**
 * Minimal policy for edge functions (no file system access)
 */
export interface EdgePolicy {
  mode: 'shadow' | 'enforce';
  inputPatterns: string[];
  outputDenylist: string[];
  refusalMessage: string;
}

/**
 * Default edge policy
 */
export const defaultEdgePolicy: EdgePolicy = {
  mode: 'shadow',
  inputPatterns: [
    '(?i)\\b(system|inner|base)[ -]?prompt\\b',
    '(?i)(ignore (previous|all) (instructions|commands))',
    '(?i)(reveal|expose|show).*(prompt|instructions)'
  ],
  outputDenylist: [
    'system prompt',
    'developer message',
    'base instructions'
  ],
  refusalMessage: "I can't share internal instructions or system prompts."
};

/**
 * Simple input check for edge functions
 * (Avoids full SPEAR dependency in Deno runtime)
 */
export function checkEdgeInput(
  content: string,
  policy: EdgePolicy = defaultEdgePolicy
): { allowed: boolean; reason?: string } {
  
  // Normalize content
  const normalized = content.normalize('NFKC').toLowerCase();
  
  // Check against patterns
  for (const pattern of policy.inputPatterns) {
    try {
      const regex = new RegExp(pattern, 'gi');
      if (regex.test(normalized)) {
        return {
          allowed: false,
          reason: `Matched block pattern: ${pattern.substring(0, 30)}...`
        };
      }
    } catch (error) {
      // Skip invalid regex
      console.error('Invalid regex pattern:', pattern);
    }
  }
  
  return { allowed: true };
}

/**
 * Simple output check for edge functions
 */
export function checkEdgeOutput(
  output: string,
  policy: EdgePolicy = defaultEdgePolicy
): { allowed: boolean; sanitized: string } {
  
  const normalized = output.toLowerCase();
  
  // Check denylist
  for (const phrase of policy.outputDenylist) {
    if (normalized.includes(phrase.toLowerCase())) {
      if (policy.mode === 'enforce') {
        return {
          allowed: false,
          sanitized: policy.refusalMessage
        };
      }
      // Shadow mode: allow but log
      console.warn('[SPEAR Shadow] Output contains deny-listed phrase:', phrase);
    }
  }
  
  return { allowed: true, sanitized: output };
}

/**
 * Wrap an edge function handler with SPEAR protection
 * 
 * Usage in edge function:
 * ```typescript
 * import { guardEdgeFunction } from 'https://esm.sh/@spear/core@0.1.0/adapters/supabase-edge';
 * 
 * serve(guardEdgeFunction(async (req, user) => {
 *   const body = await req.json();
 *   // Your logic here
 *   return { result: 'success' };
 * }));
 * ```
 */
export function guardEdgeFunction<T>(
  handler: (req: Request, user: unknown) => Promise<T>,
  policy: EdgePolicy = defaultEdgePolicy
): (req: Request) => Promise<Response> {
  
  return async (req: Request): Promise<Response> => {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    };
    
    try {
      // Parse request body for input checking
      const body = await req.json();
      const content = body.message || body.content || body.prompt || '';
      
      // Check input
      if (content) {
        const inputCheck = checkEdgeInput(content, policy);
        
        if (!inputCheck.allowed) {
          console.warn('[SPEAR] Blocked request:', inputCheck.reason);
          
          if (policy.mode === 'enforce') {
            return new Response(
              JSON.stringify({ error: policy.refusalMessage }),
              {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
              }
            );
          }
        }
      }
      
      // Call original handler (with mocked user for now)
      const result = await handler(req, null);
      
      // Check output if it's a string
      const resultString = typeof result === 'string' 
        ? result 
        : JSON.stringify(result);
      
      const outputCheck = checkEdgeOutput(resultString, policy);
      
      if (!outputCheck.allowed) {
        console.error('[SPEAR] Blocked output - potential leak detected');
        
        return new Response(
          JSON.stringify({ error: policy.refusalMessage }),
          {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          }
        );
      }
      
      // Return successful result
      return new Response(
        typeof result === 'string' ? result : JSON.stringify(result),
        {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      );
      
    } catch (error) {
      console.error('[SPEAR] Handler error:', error);
      
      return new Response(
        JSON.stringify({ error: 'Internal server error' }),
        {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      );
    }
  };
}

