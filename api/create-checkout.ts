/**
 * Checkout session creation edge gateway.
 *
 * Thin auth proxy: validates Clerk bearer token, then relays to the
 * Convex /relay/create-checkout HTTP action which runs the actual
 * Dodo checkout session creation with all validation (returnUrl
 * allowlist, HMAC signing, customer prefill).
 *
 * Used by both the /pro marketing page and the main dashboard.
 *
 * FREE MODE: returns 410 Gone immediately. Billing is disabled; all
 * features are available without a subscription. The checkout relay
 * logic is intentionally removed — if billing is re-enabled, restore
 * the Clerk token validation and Convex relay from git history.
 */

export const config = { runtime: 'edge' };

// @ts-expect-error — JS module, no declaration file
import { getCorsHeaders } from './_cors.js';

function json(body: unknown, status: number, cors: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...cors,
    },
  });
}

export default async function handler(req: Request): Promise<Response> {
  const cors = getCorsHeaders(req) as Record<string, string>;

  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        ...cors,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }

  if (req.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405, cors);
  }

  // FREE MODE: billing is disabled. All features are available for free.
  // 410 Gone signals to callers (startCheckout in checkout.ts) that this
  // endpoint is permanently unavailable, not a transient failure.
  return json(
    { error: 'Billing is disabled. All features are available for free.' },
    410,
    cors,
  );
}