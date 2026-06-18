/**
 * Entitlement enforcement middleware for the Vercel API gateway.
 *
 * FREE MODE — all entitlement checks are bypassed. Every endpoint is
 * unrestricted and every user receives a full-pro entitlement object.
 * The Redis/Convex fetch paths are dead code while this mode is active.
 *
 * To re-enable paid gating:
 *   1. Restore getRequiredTier to read from ENDPOINT_ENTITLEMENTS.
 *   2. Restore getEntitlements to the Redis→Convex fetch path (_getEntitlementsImpl).
 *   3. Restore checkEntitlement to enforce the tier comparison.
 */

import { getCachedJson, setCachedJson } from './redis';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CachedEntitlements {
  planKey: string;
  features: {
    tier: number;
    apiAccess: boolean;
    apiRateLimit: number;
    maxDashboards: number;
    prioritySupport: boolean;
    exportFormats: string[];
    /**
     * Pro MCP access (plan 2026-05-10-001). Undefined on legacy entitlement
     * rows written before the catalog field landed; every consumer
     * (gateway HMAC verifier, isCallerPremium, MCP edge handler) treats
     * undefined as `false` — fail-closed. The Dodo webhook repopulates
     * this on the next subscription event.
     */
    mcpAccess?: boolean;
  };
  validUntil: number;
}

// ---------------------------------------------------------------------------
// Endpoint-to-tier map (replaces PREMIUM_RPC_PATHS)
// ---------------------------------------------------------------------------

/**
 * Maps API endpoints to the minimum tier required for access.
 * Tier hierarchy: 0=free, 1=pro, 2=api, 3=enterprise.
 *
 * Adding a new gated endpoint = adding one line to this map.
 * Endpoints NOT in this map are unrestricted.
 *
 * Kept for reference — not consulted in free mode.
 */
const ENDPOINT_ENTITLEMENTS: Record<string, number> = {
  '/api/market/v1/analyze-stock': 1,
  '/api/market/v1/get-stock-analysis-history': 1,
  '/api/market/v1/backtest-stock': 1,
  '/api/market/v1/list-stored-stock-backtests': 1,
};

const CONVEX_INTERNAL_ENTITLEMENTS_PATH = '/api/internal-entitlements';
let _didWarnMissingConvexSharedSecret = false;

function getConvexSharedSecret(): string {
  const secret = process.env.CONVEX_SERVER_SHARED_SECRET ?? '';
  if (!secret && !_didWarnMissingConvexSharedSecret) {
    _didWarnMissingConvexSharedSecret = true;
    console.warn('[entitlement-check] CONVEX_SERVER_SHARED_SECRET not set; Convex fallback disabled');
  }
  return secret;
}

// ---------------------------------------------------------------------------
// Request coalescing (P1-6: Cache stampede mitigation)
// ---------------------------------------------------------------------------

const _inFlight = new Map<string, Promise<CachedEntitlements | null>>();

// ---------------------------------------------------------------------------
// Environment-aware Redis key prefix (P2-3)
// ---------------------------------------------------------------------------

const ENV_PREFIX = process.env.DODO_PAYMENTS_ENVIRONMENT === 'live_mode' ? 'live' : 'test';

// Cache TTL: 15 min — short enough that subscription expiry is reflected promptly (P2-5)
const ENTITLEMENT_CACHE_TTL_SECONDS = 900;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns the minimum tier required for a given endpoint pathname.
 *
 * FREE MODE: always returns null (all endpoints unrestricted).
 */
export function getRequiredTier(pathname: string): number | null {
  // Free mode — no endpoint is gated.
  // To re-enable: return ENDPOINT_ENTITLEMENTS[pathname] ?? null;
  return null;
}

/**
 * Fetches entitlements for a user.
 *
 * FREE MODE: returns a full-pro entitlement object for every user so
 * any downstream tier check behaves as unlocked.
 */
export async function getEntitlements(userId: string): Promise<CachedEntitlements | null> {
  return {
    planKey: 'pro',
    features: {
      tier: 3,
      apiAccess: true,
      apiRateLimit: Number.MAX_SAFE_INTEGER,
      maxDashboards: 1000,
      prioritySupport: true,
      exportFormats: ['csv', 'json', 'xlsx'],
      mcpAccess: true,
    },
    validUntil: Number.MAX_SAFE_INTEGER,
  };
}

/**
 * Real fetch path — kept intact for when paid gating is re-enabled.
 * Not called in free mode.
 */
async function _getEntitlementsImpl(userId: string): Promise<CachedEntitlements | null> {
  try {
    // Redis cache check (raw=true: entitlements use user-scoped keys, no deployment prefix)
    const cached = await getCachedJson(`entitlements:${ENV_PREFIX}:${userId}`, true);

    if (cached && typeof cached === 'object') {
      const ent = cached as CachedEntitlements;
      // Only use cached data if it hasn't expired AND has the post-U10 shape.
      //
      // Legacy cache entries written before plan 2026-05-10-001 U10 lack the
      // `features.mcpAccess` field. The Convex read path read-time-merges
      // catalog defaults (convex/entitlements.ts:50), but bare-cache reads
      // bypass that merge — paying users with hot pre-deploy cache entries
      // would see `mcpAccess !== true` at the grant/MCP gates and get
      // blocked for up to 15 min until the cache expires. Treating
      // missing-field cache entries as stale falls through to Convex,
      // which returns the merged shape and rewrites the cache with the
      // post-U10 layout. Self-healing, bounded to one extra Convex
      // round-trip per affected user during the migration window.
      if (
        ent.validUntil >= Date.now() &&
        typeof (ent.features as { mcpAccess?: boolean }).mcpAccess === 'boolean'
      ) {
        return ent;
      }
      // Expired OR legacy shape -- fall through to Convex.
    }

    // Convex fallback on cache miss or expired cache
    const convexSiteUrl = process.env.CONVEX_SITE_URL;
    const convexSharedSecret = getConvexSharedSecret();
    if (!convexSiteUrl || !convexSharedSecret) return null;

    const response = await fetch(`${convexSiteUrl}${CONVEX_INTERNAL_ENTITLEMENTS_PATH}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'worldmonitor-gateway/1.0',
        'x-convex-shared-secret': convexSharedSecret,
      },
      body: JSON.stringify({ userId }),
    });
    if (!response.ok) return null;
    const result = await response.json() as CachedEntitlements | null;

    if (result) {
      // Populate Redis cache for subsequent requests (15-min TTL, raw key).
      //
      // Cache-write failures must NOT collapse "entitlement confirmed by Convex"
      // into the null-means-no-entitlement return.
      try {
        await setCachedJson(`entitlements:${ENV_PREFIX}:${userId}`, result, ENTITLEMENT_CACHE_TTL_SECONDS, true);
      } catch (cacheErr) {
        console.warn('[entitlement-check] cache write failed (non-fatal):', cacheErr instanceof Error ? cacheErr.message : String(cacheErr));
      }
      return result as CachedEntitlements;
    }

    return null;
  } catch (err) {
    // Fail-closed: any error in entitlement lookup returns null (caller blocks the request)
    console.warn('[entitlement-check] getEntitlements failed:', err instanceof Error ? err.message : String(err));
    return null;
  }
}

/**
 * Checks whether the current request is allowed based on tier entitlements.
 *
 * FREE MODE: always returns null (request allowed). The 403 path is
 * unreachable while getRequiredTier returns null for every pathname.
 *
 * Returns:
 *   - null if the request is allowed (unrestricted endpoint or sufficient tier)
 *   - a 403 Response if the user is unauthenticated, entitlements cannot be
 *     verified, or the user's tier is below the required tier (fail-closed)
 */
export async function checkEntitlement(
  userId: string | null,
  pathname: string,
  corsHeaders: Record<string, string>,
): Promise<Response | null> {
  // Free mode — getRequiredTier always returns null, so every request is
  // unrestricted. Return null (allow) immediately.
  const requiredTier = getRequiredTier(pathname);
  if (requiredTier === null) return null;

  // The block below is only reached when getRequiredTier is restored to
  // return real tier values. It is intentionally kept so re-enabling paid
  // gating requires only restoring getRequiredTier, not re-authoring the
  // enforcement logic.
  if (!userId) {
    return new Response(
      JSON.stringify({ error: 'Authentication required' }),
      { status: 403, headers: { 'Content-Type': 'application/json', ...corsHeaders } },
    );
  }

  const entitlements = await getEntitlements(userId);
  if (!entitlements) {
    return new Response(
      JSON.stringify({ error: 'Unable to verify entitlements' }),
      { status: 403, headers: { 'Content-Type': 'application/json', ...corsHeaders } },
    );
  }

  if (entitlements.features.tier < requiredTier) {
    return new Response(
      JSON.stringify({ error: 'Insufficient tier for this endpoint' }),
      { status: 403, headers: { 'Content-Type': 'application/json', ...corsHeaders } },
    );
  }

  return null;
}