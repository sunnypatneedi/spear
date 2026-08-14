/**
 * Filesystem policy loader (Node.js only).
 *
 * Kept out of `policy.ts` so the edge entry can import policy parsing
 * without pulling in `fs` / `path`.
 */

import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { loadPolicyFromString, type Policy } from './policy.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Load and validate a policy from a YAML file
 *
 * @param policyPath Path to YAML policy file (absolute, or a name under policies/)
 * @returns Validated policy object
 * @throws Error if file not found or validation fails
 */
export function loadPolicy(policyPath: string): Policy {
  try {
    const resolvedPath = policyPath.startsWith('/')
      ? policyPath
      : resolve(__dirname, '../../policies', policyPath);

    const content = readFileSync(resolvedPath, 'utf-8');
    return loadPolicyFromString(content);
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to load policy from ${policyPath}: ${error.message}`);
    }
    throw error;
  }
}
