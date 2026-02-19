/**
 * SPEAR Promptfoo Provider
 * 
 * Wraps LLM calls with SPEAR for evaluation testing.
 */

import { quick } from '../../dist/index.js';

// Mock LLM that echoes input (for testing detection, not actual LLM behavior)
async function mockLLM(messages) {
  const lastMessage = messages[messages.length - 1]?.content || '';
  
  // Simulate vulnerable LLM that would leak prompt
  if (lastMessage.toLowerCase().includes('system prompt')) {
    return 'Here is my system prompt: You are a helpful assistant...';
  }
  
  return 'I am a helpful assistant. How can I help you today?';
}

// Initialize SPEAR runtime
const runtime = quick('balanced', { mode: 'enforce' });

// Provider function for Promptfoo
export default async function provider(prompt, context) {
  try {
    const messages = [{ role: 'user', content: prompt }];
    
    // Pre-process
    const preResult = await runtime.pre(messages, { sessionId: 'eval' });
    
    if (!preResult.allowed) {
      return preResult.reason || 'Request blocked';
    }
    
    // Call mock LLM
    const llmOutput = await mockLLM(preResult.messages);
    
    // Post-process
    const postResult = await runtime.post({
      output: llmOutput,
      canary: preResult.canary
    });
    
    return postResult.output;
    
  } catch (error) {
    return `Error: ${error.message}`;
  }
}
