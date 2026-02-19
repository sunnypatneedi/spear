/**
 * @spear/ai-sdk
 *
 * SPEAR integration for Vercel AI SDK
 * Provides multi-provider LLM security through a drop-in wrapper
 */

export { wrapLanguageModel, createGuardedModel } from './wrapper.js';
export type { SpearWrapperOptions } from './wrapper.js';
