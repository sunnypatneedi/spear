/**
 * Multi-tenant policy namespacing.
 *
 * Tenants may tighten the base policy but cannot weaken it:
 * - `enforce` cannot be overridden to `shadow`
 * - canaries cannot be disabled if the base policy has them on
 */

import { mergePolicy, type Policy } from './policy.js';

/**
 * Registry mapping tenant IDs to policy overlays on a shared base.
 */
export class PolicyRegistry {
  private overlays = new Map<string, Partial<Policy>>();

  /**
   * @param base Shared baseline policy applied to every tenant
   */
  constructor(private readonly base: Policy) {}

  /**
   * Register (or replace) a tenant overlay. Invalid weakenings throw.
   *
   * @param tenantId Tenant identifier
   * @param overlay Partial policy overlay
   */
  register(tenantId: string, overlay: Partial<Policy>): void {
    this.assertInvariant(overlay);
    this.overlays.set(tenantId, overlay);
  }

  /**
   * Remove a tenant overlay.
   *
   * @param tenantId Tenant identifier
   */
  unregister(tenantId: string): void {
    this.overlays.delete(tenantId);
  }

  /**
   * Resolve the effective policy for a tenant. Unknown tenants get the base.
   *
   * @param tenantId Tenant identifier
   */
  resolve(tenantId: string): Policy {
    const overlay = this.overlays.get(tenantId);
    if (!overlay) return this.base;
    return mergePolicy(this.base, overlay);
  }

  /** The unmodified base policy. */
  getBase(): Policy {
    return this.base;
  }

  /** Number of registered tenant overlays. */
  get size(): number {
    return this.overlays.size;
  }

  private assertInvariant(overlay: Partial<Policy>): void {
    if (this.base.mode === 'enforce' && overlay.mode === 'shadow') {
      throw new Error('Tenants cannot weaken base policy mode from enforce to shadow');
    }
    if (this.base.canary.enabled && overlay.canary && overlay.canary.enabled === false) {
      throw new Error('Tenants cannot disable the canary system');
    }
  }
}
