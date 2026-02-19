/**
 * Supabase Edge Function + SPEAR Example
 *
 * Deploy this to Supabase as an edge function
 */

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// In a real edge function, you'd import from the deployed package
// For now, this demonstrates the API structure

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    // Create Supabase client
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: {
          headers: { Authorization: req.headers.get('Authorization')! },
        },
      }
    );

    // Get user from auth
    const {
      data: { user },
    } = await supabaseClient.auth.getUser();

    if (!user) {
      throw new Error('Unauthorized');
    }

    // Parse request
    const { messages, policy = 'balanced', mode = 'enforce' } = await req.json();

    // In production, you'd use @spear/supabase here:
    // import { guardLLMCall } from '@spear/supabase';
    // const result = await guardLLMCall(messages, { policy, mode });

    // For this example, we'll demonstrate the structure
    const result = {
      allowed: true,
      messages,
      sanitizedOutput: 'This would be the LLM response after SPEAR protection',
      telemetry: {
        blocked: false,
        reason: null,
        sessionId: user.id,
      },
    };

    return new Response(JSON.stringify(result), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
