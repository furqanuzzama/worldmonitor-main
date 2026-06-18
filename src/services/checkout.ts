/**
 * Checkout overlay orchestration service.
 *
 * Manages the full checkout lifecycle in the vanilla TS dashboard:
 * - Lazy-initializes the Dodo Payments overlay SDK
 * - Creates checkout sessions via the Convex createCheckout action
 * - Opens the overlay with dark-theme styling matching the dashboard
 * - Stores pending checkout intents for /pro handoff flows
 * - Handles overlay events (success, error, close)
 *
 * UI code calls startCheckout(productId) -- everything else is internal.
 *
 * FREE MODE: startCheckout, initCheckoutOverlay, and openCheckout are
 * no-ops. Billing is disabled; all features are available for free.
 * The full checkout flow below is preserved for re-enabling paid gating.
 */

import { enqueueSentryCall } from '@/bootstrap/sentry-defer';
import { DodoPayments } from 'dodopayments-checkout';
import type { CheckoutEvent } from 'dodopayments-checkout';
import { openBillingPortal, prereserveBillingPortalTab } from './billing';
import { getCurrentClerkUser, getClerkToken, openSignIn } from './clerk';
import { subscribeAuthState } from './auth-state';
import { saveCheckoutAttempt, clearCheckoutAttempt } from './checkout-attempt';
import {
  classifyHttpCheckoutError,
  classifySyntheticCheckoutError,
  classifyThrownCheckoutError,
  parseCheckoutErrorBody,
  snapshotUpstreamResponse,
  type CheckoutError,
  type CheckoutErrorBody,
  type CheckoutErrorCode,
  type UpstreamSnapshot,
} from './checkout-errors';
import { showCheckoutErrorToast } from './checkout-error-toast';
import { decideNoUserPathOutcome } from './checkout-no-user-policy';
import { shouldSkipSentryForAction } from './checkout-sentry-policy';
import { isEntitled, onEntitlementChange } from './entitlements';
import {
  CLASSIC_AUTO_DISMISS_MS,
  EXTENDED_UNLOCK_TIMEOUT_MS,
  maskEmail,
  type CheckoutSuccessBannerState,
} from './checkout-banner-state';
import { loadActiveReferral } from './referral-capture';
import { showDuplicateSubscriptionDialog } from './checkout-duplicate-dialog';
import { resolvePlanDisplayName } from './checkout-plan-names';
import { createEntitlementWatchdog, type EntitlementWatchdog } from './entitlement-watchdog';

export {
  EXTENDED_UNLOCK_TIMEOUT_MS,
  maskEmail,
  type CheckoutSuccessBannerState,
} from './checkout-banner-state';

export {
  saveCheckoutAttempt,
  loadCheckoutAttempt,
  clearCheckoutAttempt,
  type CheckoutAttempt,
  type CheckoutAttemptClearReason,
} from './checkout-attempt';

const CHECKOUT_PRODUCT_PARAM = 'checkoutProduct';
const CHECKOUT_REFERRAL_PARAM = 'checkoutReferral';
const CHECKOUT_DISCOUNT_PARAM = 'checkoutDiscount';
const PENDING_CHECKOUT_KEY = 'wm-pending-checkout';
const POST_CHECKOUT_FLAG_KEY = 'wm-post-checkout';
const APP_CHECKOUT_BASE_URL = 'https://worldmonitor.app/dashboard';

/**
 * Session flag set just before the post-overlay reload. Lets panel-layout
 * detect "we just returned from an overlay checkout" on the reloaded page —
 * the overlay uses manualRedirect:true so there are no subscription_id URL
 * params to key off, unlike the full-page redirect return handled by
 * handleCheckoutReturn. Exported as a pair (consume+mark) to keep the key
 * centralized with the rest of the checkout storage constants.
 */
export function consumePostCheckoutFlag(): boolean {
  try {
    if (sessionStorage.getItem(POST_CHECKOUT_FLAG_KEY) === '1') {
      sessionStorage.removeItem(POST_CHECKOUT_FLAG_KEY);
      return true;
    }
  } catch {
    // Private browsing / storage disabled — fall through to false.
  }
  return false;
}

function markPostCheckout(): void {
  try {
    sessionStorage.setItem(POST_CHECKOUT_FLAG_KEY, '1');
  } catch {
    // Storage denied — the reload will still run; transition detector will
    // fall back to its null baseline, matching the pre-flag behavior.
  }
}

interface PendingCheckoutIntent {
  productId: string;
  referralCode?: string;
  discountCode?: string;
  /**
   * User id who saved this intent, or null if saved anonymously (the
   * common "click Buy, get sign-in modal" path). On resume, we only
   * fire the auto-checkout if:
   *   - savedByUserId === current user id (mid-flow redirect return), OR
   *   - savedByUserId === null AND current user is authenticated
   *     (anonymous intent → user just signed up/in — THIS IS the
   *     auto-resume case)
   * Anything else (A saved, B is now signed in) is a cross-user leak
   * and the intent is discarded.
   */
  savedByUserId?: string | null;
  /**
   * Unix-ms when this intent was saved. Stale intents (closed Clerk
   * modal without signing in, then hours later another sign-in for
   * unrelated reasons) must not auto-resume checkout — the user's
   * intent to buy has expired. Loaders apply PENDING_INTENT_TTL_MS
   * and discard anything older.
   */
  savedAt?: number;
}

/**
 * Max age of a saved pending-checkout intent before auto-resume is
 * suppressed. 15 minutes covers a typical sign-in round-trip (read
 * the dialog, switch to password manager, go through verification)
 * without leaking into the "unrelated sign-in much later" case that
 * previously fired a stale checkout. Matches the "user walked away
 * from the flow" threshold — longer than that and we treat a later
 * sign-in as unrelated.
 */
const PENDING_INTENT_TTL_MS = 15 * 60 * 1000;

let initialized = false;
let onSuccessCallback: (() => void) | null = null;
let _resetOverlaySession: (() => void) | null = null;
let _watchersInitialized = false;
let _escapeHandler: ((e: KeyboardEvent) => void) | null = null;

/**
 * Entitlement watchdog tuning.
 * Kept for reference — not used in free mode.
 */
const WATCHDOG_INTERVAL_MS = 3_000;
const WATCHDOG_TIMEOUT_MS = 10 * 60 * 1000;

function safeCloseOverlay(): void {
  try {
    if (DodoPayments.Checkout.isOpen?.()) {
      DodoPayments.Checkout.close();
    }
  } catch {
    // Swallow — the overlay is already gone or the SDK is mid-teardown.
  }
}

/**
 * Initialize the Dodo overlay SDK. Idempotent -- second+ calls are no-ops.
 *
 * FREE MODE: no-op. The Dodo SDK is never initialized so no iframe or
 * payment overlay is ever mounted. To re-enable: remove the early return.
 */
export function initCheckoutOverlay(onSuccess?: () => void): void {
  // Free mode — billing disabled, skip SDK initialization entirely.
  return;

  // -------------------------------------------------------------------------
  // Unreachable in free mode. Preserved for re-enabling paid gating.
  // -------------------------------------------------------------------------
  if (initialized) return;

  if (onSuccess) {
    onSuccessCallback = onSuccess;
  }

  const env = import.meta.env.VITE_DODO_ENVIRONMENT;

  let successFired = false;
  let navigationFired = false;
  let watchdog: EntitlementWatchdog | null = null;

  const stopWatchdog = (): void => {
    watchdog?.stop();
    watchdog = null;
  };

  _resetOverlaySession = () => {
    successFired = false;
    navigationFired = false;
    stopWatchdog();
  };

  const runTerminalSuccessSideEffects = (reason: 'event-status' | 'event-redirect' | 'watchdog'): void => {
    if (successFired) return;
    successFired = true;
    stopWatchdog();

    enqueueSentryCall((s) => s.addBreadcrumb({
      category: 'checkout',
      message: `terminal success (${reason})`,
      level: 'info',
      data: { reason },
    }));
    if (reason === 'watchdog') {
      enqueueSentryCall((s) => s.captureMessage('Dodo wallet-return deadlock — watchdog resolved', {
        level: 'info',
        tags: { component: 'dodo-checkout', code: 'watchdog_resolved' },
      }));
    }

    try {
      onSuccessCallback?.();
    } catch (err) {
      console.error('[checkout] onSuccessCallback threw:', err);
      enqueueSentryCall((s) => s.captureException(err, {
        tags: { component: 'dodo-checkout', action: 'on-success' },
      }));
    }
    clearCheckoutAttempt('success');
    clearPendingCheckoutIntent();
    markPostCheckout();
  };

  const startWatchdog = (): void => {
    if (watchdog !== null || successFired) return;
    watchdog = createEntitlementWatchdog(
      {
        endpoint: '/api/me/entitlement',
        intervalMs: WATCHDOG_INTERVAL_MS,
        timeoutMs: WATCHDOG_TIMEOUT_MS,
      },
      {
        getToken: getClerkToken,
        fetch: (input, init) => fetch(input, init),
        setInterval: (cb, ms) => window.setInterval(cb, ms),
        clearInterval: (id) => window.clearInterval(id),
        now: () => Date.now(),
        onPro: () => {
          runTerminalSuccessSideEffects('watchdog');
          safeCloseOverlay();
        },
      },
    );
    watchdog.start();
  };

  DodoPayments.Initialize({
    mode: env === 'live_mode' ? 'live' : 'test',
    displayType: 'overlay',
    onEvent: (event: CheckoutEvent) => {
      switch (event.event_type) {
        case 'checkout.opened':
          startWatchdog();
          break;
        case 'checkout.status': {
          const rawData = event.data as Record<string, unknown> | undefined;
          const status = (rawData?.message as Record<string, unknown> | undefined)?.status;
          if (status === 'succeeded') {
            runTerminalSuccessSideEffects('event-status');
          }
          break;
        }
        case 'checkout.closed':
          stopWatchdog();
          if (!successFired) {
            clearPendingCheckoutIntent();
          }
          break;
        case 'checkout.redirect_requested': {
          const redirectTo = (event.data?.message as Record<string, unknown> | undefined)?.redirect_to as string | undefined;
          if (!successFired) runTerminalSuccessSideEffects('event-redirect');
          if (redirectTo && !navigationFired) {
            navigationFired = true;
            window.location.href = redirectTo;
          }
          break;
        }
        case 'checkout.error':
          console.error('[checkout] Overlay error:', event.data?.message);
          enqueueSentryCall((s) => s.captureMessage(`Dodo checkout overlay error: ${event.data?.message || 'unknown'}`, { level: 'error', tags: { component: 'dodo-checkout' } }));
          stopWatchdog();
          safeCloseOverlay();
          break;
      }
    },
  });

  _escapeHandler = (e: KeyboardEvent) => {
    if (e.key === 'Escape' && DodoPayments.Checkout.isOpen?.()) {
      safeCloseOverlay();
    }
  };
  window.addEventListener('keydown', _escapeHandler);

  initialized = true;
}

/**
 * Destroy the checkout overlay — resets initialized flag and clears the
 * stored success callback so a new layout can register its own callback.
 */
export function destroyCheckoutOverlay(): void {
  // _resetOverlaySession is null in free mode (initCheckoutOverlay never
  // sets it), so this is effectively a no-op. Kept intact so callers
  // don't need to change when billing is re-enabled.
  _resetOverlaySession?.();
  _resetOverlaySession = null;
  initialized = false;
  onSuccessCallback = null;
  if (_escapeHandler) {
    window.removeEventListener('keydown', _escapeHandler);
    _escapeHandler = null;
  }
}

function loadPendingCheckoutIntent(): PendingCheckoutIntent | null {
  try {
    const raw = sessionStorage.getItem(PENDING_CHECKOUT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as PendingCheckoutIntent;
    if (typeof parsed.savedAt !== 'number' || Date.now() - parsed.savedAt > PENDING_INTENT_TTL_MS) {
      clearPendingCheckoutIntent();
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function savePendingCheckoutIntent(intent: PendingCheckoutIntent): void {
  try {
    const stamped: PendingCheckoutIntent = {
      ...intent,
      savedAt: intent.savedAt ?? Date.now(),
    };
    sessionStorage.setItem(PENDING_CHECKOUT_KEY, JSON.stringify(stamped));
  } catch {
    // Ignore storage failures.
  }
}

function clearPendingCheckoutIntent(): void {
  try {
    sessionStorage.removeItem(PENDING_CHECKOUT_KEY);
  } catch {
    // Ignore storage failures.
  }
}

/**
 * Wire lifecycle watchers for auth-state changes.
 * Kept fully intact — these manage session storage cleanup on sign-in/
 * sign-out and are not specific to paid billing flows.
 */
export function initCheckoutWatchers(): void {
  if (_watchersInitialized) return;
  _watchersInitialized = true;

  let _lastUserId: string | null = null;
  let _initialized = false;
  subscribeAuthState((state) => {
    const nextId = state.user?.id ?? null;
    if (!_initialized) {
      _initialized = true;
      _lastUserId = nextId;
      if (nextId === null) {
        clearCheckoutAttempt('signout');
        clearPendingCheckoutIntent();
        try { sessionStorage.removeItem(POST_CHECKOUT_FLAG_KEY); } catch { /* ignore */ }
      }
      return;
    }
    if (nextId !== _lastUserId) {
      const isSignIn = _lastUserId === null && nextId !== null;
      if (isSignIn) {
        // Do NOT clear pending / post-checkout on sign-in.
      } else {
        clearCheckoutAttempt('signout');
        clearPendingCheckoutIntent();
        try { sessionStorage.removeItem(POST_CHECKOUT_FLAG_KEY); } catch { /* ignore */ }
      }
    }
    _lastUserId = nextId;
  });
}

export function buildCheckoutLaunchUrl(
  productId: string,
  options?: { referralCode?: string; discountCode?: string },
): string {
  const url = new URL(APP_CHECKOUT_BASE_URL);
  url.searchParams.set(CHECKOUT_PRODUCT_PARAM, productId);
  if (options?.referralCode) {
    url.searchParams.set(CHECKOUT_REFERRAL_PARAM, options.referralCode);
  }
  if (options?.discountCode) {
    url.searchParams.set(CHECKOUT_DISCOUNT_PARAM, options.discountCode);
  }
  return url.toString();
}

export function capturePendingCheckoutIntentFromUrl(): PendingCheckoutIntent | null {
  const url = new URL(window.location.href);
  const productId = url.searchParams.get(CHECKOUT_PRODUCT_PARAM);
  if (!productId) return null;

  console.log(`[checkout] Captured intent from URL: product=${productId}`);

  const intent: PendingCheckoutIntent = {
    productId,
    referralCode: url.searchParams.get(CHECKOUT_REFERRAL_PARAM) ?? undefined,
    discountCode: url.searchParams.get(CHECKOUT_DISCOUNT_PARAM) ?? undefined,
    savedByUserId: getCurrentClerkUser()?.id ?? null,
  };
  savePendingCheckoutIntent(intent);
  saveCheckoutAttempt({
    productId,
    referralCode: intent.referralCode,
    discountCode: intent.discountCode,
    startedAt: Date.now(),
  });

  url.searchParams.delete(CHECKOUT_PRODUCT_PARAM);
  url.searchParams.delete(CHECKOUT_REFERRAL_PARAM);
  url.searchParams.delete(CHECKOUT_DISCOUNT_PARAM);
  const cleanUrl = url.pathname + (url.searchParams.toString() ? `?${url.searchParams.toString()}` : '') + url.hash;
  window.history.replaceState({}, '', cleanUrl);

  return intent;
}

export async function resumePendingCheckout(options?: {
  openAuth?: () => void;
}): Promise<boolean> {
  // FREE MODE: startCheckout is a no-op, so this is too.
  return false;
}

/**
 * Open the Dodo checkout overlay for a given checkout URL.
 *
 * FREE MODE: no-op. The overlay SDK is never initialized, so opening it
 * would throw. To re-enable: remove the early return.
 */
export function openCheckout(checkoutUrl: string): void {
  // Free mode — billing disabled, do not open the payment overlay.
  return;

  // -------------------------------------------------------------------------
  // Unreachable in free mode. Preserved for re-enabling paid gating.
  // -------------------------------------------------------------------------
  initCheckoutOverlay();
  _resetOverlaySession?.();

  DodoPayments.Checkout.open({
    checkoutUrl,
    options: {
      manualRedirect: true,
      themeConfig: {
        dark: {
          bgPrimary: '#0d0d0d',
          bgSecondary: '#1a1a1a',
          borderPrimary: '#323232',
          textPrimary: '#ffffff',
          textSecondary: '#909090',
          buttonPrimary: '#22c55e',
          buttonPrimaryHover: '#16a34a',
          buttonTextPrimary: '#0d0d0d',
        },
        light: {
          bgPrimary: '#ffffff',
          bgSecondary: '#f8f9fa',
          borderPrimary: '#d4d4d4',
          textPrimary: '#1a1a1a',
          textSecondary: '#555555',
          buttonPrimary: '#16a34a',
          buttonPrimaryHover: '#15803d',
          buttonTextPrimary: '#ffffff',
        },
        radius: '4px',
      },
    },
  });
}

let _checkoutInFlight = false;

/**
 * High-level checkout entry point for UI code.
 *
 * FREE MODE: returns false immediately without making any network request,
 * showing any error, or redirecting anywhere. All features are already
 * available for free so there is nothing to purchase. To re-enable:
 * remove the early return.
 */
export async function startCheckout(
  productId: string,
  options?: { discountCode?: string; referralCode?: string },
  behavior?: { fallbackToPricingPage?: boolean },
): Promise<boolean> {
  // Free mode — billing disabled, silently decline all checkout attempts.
  console.info('[checkout] startCheckout called in free mode — billing is disabled');
  return false;

  // -------------------------------------------------------------------------
  // Unreachable in free mode. Preserved for re-enabling paid gating.
  // -------------------------------------------------------------------------
  if (_checkoutInFlight) return false;
  const fallbackToPricingPage = behavior?.fallbackToPricingPage ?? true;

  const user = getCurrentClerkUser();
  if (!user) {
    const intent = {
      productId,
      referralCode: options?.referralCode,
      discountCode: options?.discountCode,
    };
    reportCheckoutError(
      classifySyntheticCheckoutError('unauthorized'),
      { productId, action: 'no-user' },
    );
    const outcome = decideNoUserPathOutcome(fallbackToPricingPage);
    if (outcome.kind === 'redirect-pro') {
      window.location.assign(outcome.redirectUrl);
    } else {
      savePendingCheckoutIntent(intent);
      saveCheckoutAttempt({
        ...intent,
        startedAt: Date.now(),
      });
      openSignIn();
    }
    return false;
  }

  _checkoutInFlight = true;
  _resetOverlaySession?.();
  const effectiveReferral = options?.referralCode ?? loadActiveReferral() ?? undefined;
  saveCheckoutAttempt({
    productId,
    referralCode: effectiveReferral,
    discountCode: options?.discountCode,
    startedAt: Date.now(),
  });
  try {
    let token = await getClerkToken();
    if (!token) {
      await new Promise((r) => setTimeout(r, 2000));
      token = await getClerkToken();
    }
    if (!token) {
      const error = classifySyntheticCheckoutError('session_expired');
      reportCheckoutError(error, { productId, action: 'no-token' });
      renderCheckoutErrorSurface(error, fallbackToPricingPage);
      return false;
    }

    const resp = await fetch('/api/create-checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        productId,
        returnUrl: window.location.origin,
        discountCode: options?.discountCode,
        referralCode: effectiveReferral,
      }),
      signal: AbortSignal.timeout(15_000),
    });

    if (!resp.ok) {
      const rawText = await resp.text().catch(() => '');
      const upstream = snapshotUpstreamResponse(resp, rawText);
      const body = parseCheckoutErrorBody(rawText);
      const error = classifyHttpCheckoutError(resp.status, body);
      reportCheckoutError(error, { productId, action: 'http-error' }, undefined, upstream);
      if (error.code === 'duplicate_subscription') {
        clearPendingCheckoutIntent();
        clearCheckoutAttempt('duplicate');
        const planKey = (body as CheckoutErrorBody & { subscription?: { planKey?: unknown } })
          ?.subscription?.planKey;
        const planDisplayName = resolvePlanDisplayName(planKey);
        showDuplicateSubscriptionDialog({
          planDisplayName,
          onConfirm: () => {
            const reservedWin = prereserveBillingPortalTab();
            void openBillingPortal(reservedWin);
          },
          onDismiss: () => { /* user stays on the dashboard */ },
        });
        return false;
      }
      if (error.code === 'unauthorized' || error.code === 'session_expired') {
        savePendingCheckoutIntent({
          productId,
          referralCode: options?.referralCode,
          discountCode: options?.discountCode,
        });
        openSignIn();
        return false;
      }
      renderCheckoutErrorSurface(error, fallbackToPricingPage);
      return false;
    }

    const result = await resp.json();
    if (result?.checkout_url) {
      openCheckout(result.checkout_url);
      return true;
    }
    const missingUrlError: CheckoutError = {
      code: 'service_unavailable',
      userMessage: 'Checkout is temporarily unavailable. Please try again in a moment.',
      serverMessage: 'Server returned 200 without a checkout_url',
      httpStatus: resp.status,
      retryable: true,
    };
    reportCheckoutError(missingUrlError, { productId, action: 'missing-checkout-url' });
    renderCheckoutErrorSurface(missingUrlError, fallbackToPricingPage);
    return false;
  } catch (err) {
    const error = classifyThrownCheckoutError(err);
    reportCheckoutError(error, { productId, action: 'exception' }, err);
    renderCheckoutErrorSurface(error, fallbackToPricingPage);
    return false;
  } finally {
    _checkoutInFlight = false;
  }
}

type SentryLevel = 'error' | 'info';
const INFO_LEVEL_CODES: ReadonlySet<CheckoutErrorCode> = new Set([
  'unauthorized',
  'session_expired',
]);

function reportCheckoutError(
  error: CheckoutError,
  context: { productId: string; action: string },
  caught?: unknown,
  upstream?: UpstreamSnapshot,
): void {
  const level: SentryLevel = INFO_LEVEL_CODES.has(error.code) ? 'info' : 'error';
  const payload = {
    level,
    tags: {
      component: 'dodo-checkout',
      action: context.action,
      code: error.code,
      ...(upstream?.cfRay ? { cfRay: upstream.cfRay } : {}),
      ...(upstream?.server ? { upstreamServer: upstream.server } : {}),
    },
    extra: {
      productId: context.productId,
      httpStatus: error.httpStatus,
      serverMessage: error.serverMessage,
      ...(upstream ? { upstream } : {}),
    },
  };
  if (!shouldSkipSentryForAction(context.action)) {
    if (caught) {
      enqueueSentryCall((s) => s.captureException(caught, payload));
    } else {
      enqueueSentryCall((s) => s.captureMessage(`Checkout error: ${error.code}`, payload));
    }
  }
  const logger = level === 'info' ? console.info : console.error;
  logger(
    `[checkout] ${error.code}${error.httpStatus ? ` (HTTP ${error.httpStatus})` : ''}`,
    error.serverMessage ?? '',
  );
}

function renderCheckoutErrorSurface(
  error: CheckoutError,
  fallbackToPricingPage: boolean,
): void {
  if (fallbackToPricingPage) {
    window.location.assign('https://worldmonitor.app/pro');
    return;
  }
  showCheckoutErrorToast(error.userMessage);
}

/**
 * Show the post-checkout success banner.
 * Kept intact — isEntitled() always returns true in free mode so the
 * banner immediately hits the fast-path and auto-dismisses after
 * CLASSIC_AUTO_DISMISS_MS. No behavior change for callers.
 */
let _currentBannerCleanup: (() => void) | null = null;

export function showCheckoutSuccess(
  options?: { waitForEntitlement?: boolean; email?: string | null },
): void {
  _currentBannerCleanup?.();
  _currentBannerCleanup = null;

  const existing = document.getElementById('checkout-success-banner');
  if (existing) existing.remove();

  const banner = document.createElement('div');
  banner.id = 'checkout-success-banner';
  Object.assign(banner.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    right: '0',
    zIndex: '99999',
    padding: '14px 20px',
    background: 'linear-gradient(135deg, #16a34a, #22c55e)',
    color: '#fff',
    fontWeight: '600',
    fontSize: '14px',
    textAlign: 'center',
    boxShadow: '0 2px 12px rgba(0,0,0,0.3)',
    transition: 'opacity 0.4s ease, transform 0.4s ease',
    transform: 'translateY(-100%)',
    opacity: '0',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '12px',
  });

  let currentMaskedEmail = maskEmail(options?.email);
  let unsubscribeAuth: (() => void) | null = null;
  let emailPollInterval: ReturnType<typeof setInterval> | null = null;
  let currentState: CheckoutSuccessBannerState = 'pending';

  const applyEmail = (raw: string | null | undefined): boolean => {
    const next = maskEmail(raw ?? null);
    if (next && next !== currentMaskedEmail) {
      currentMaskedEmail = next;
      setBannerText(banner, currentState, currentMaskedEmail);
      stopEmailWatchers();
      return true;
    }
    return false;
  };
  const stopEmailWatchers = (): void => {
    unsubscribeAuth?.();
    unsubscribeAuth = null;
    if (emailPollInterval) {
      clearInterval(emailPollInterval);
      emailPollInterval = null;
    }
  };

  if (!currentMaskedEmail) {
    unsubscribeAuth = subscribeAuthState((state) => {
      applyEmail(state.user?.email);
    });
    const POLL_MS = 500;
    const POLL_BUDGET_MS = 15_000;
    const pollStart = Date.now();
    emailPollInterval = setInterval(() => {
      if (Date.now() - pollStart > POLL_BUDGET_MS) {
        if (emailPollInterval) { clearInterval(emailPollInterval); emailPollInterval = null; }
        return;
      }
      applyEmail(getCurrentClerkUser()?.email);
    }, POLL_MS);
  }
  setBannerText(banner, 'pending', currentMaskedEmail);
  document.body.appendChild(banner);

  requestAnimationFrame(() => {
    banner.style.transform = 'translateY(0)';
    banner.style.opacity = '1';
  });

  if (!options?.waitForEntitlement) {
    setTimeout(() => {
      stopEmailWatchers();
      dismissBanner(banner);
    }, CLASSIC_AUTO_DISMISS_MS);
    return;
  }

  // isEntitled() always returns true in free mode — this fast-path fires
  // immediately and auto-dismisses the banner.
  if (isEntitled()) {
    currentState = 'active';
    setBannerText(banner, 'active', currentMaskedEmail);
    setTimeout(() => {
      stopEmailWatchers();
      dismissBanner(banner);
    }, CLASSIC_AUTO_DISMISS_MS);
    return;
  }

  let resolved = false;
  const timeoutHandle = setTimeout(() => {
    if (resolved) return;
    resolved = true;
    unsubscribe();
    stopEmailWatchers();
    _currentBannerCleanup = null;
    currentState = 'timeout';
    setBannerText(banner, 'timeout', currentMaskedEmail);
    enqueueSentryCall((s) => s.captureMessage('Checkout entitlement-activation timeout', {
      level: 'warning',
      tags: { component: 'dodo-checkout', action: 'entitlement-timeout' },
    }));
  }, EXTENDED_UNLOCK_TIMEOUT_MS);

  const unsubscribe = onEntitlementChange(() => {
    if (resolved) return;
    if (!isEntitled()) return;
    resolved = true;
    clearTimeout(timeoutHandle);
    unsubscribe();
    stopEmailWatchers();
    _currentBannerCleanup = null;
    currentState = 'active';
    setBannerText(banner, 'active', currentMaskedEmail);
  });

  _currentBannerCleanup = () => {
    if (resolved) return;
    resolved = true;
    clearTimeout(timeoutHandle);
    unsubscribe();
  };
}

function setBannerText(
  banner: HTMLElement,
  state: CheckoutSuccessBannerState,
  maskedEmail: string | null,
): void {
  banner.setAttribute('data-entitlement-state', state);
  if (state === 'pending') {
    banner.textContent = maskedEmail
      ? `Payment received! Receipt sent to ${maskedEmail}. Unlocking your premium features…`
      : 'Payment received! Unlocking your premium features…';
    return;
  }
  if (state === 'active') {
    banner.textContent = 'Premium activated — reloading…';
    return;
  }
  // timeout
  banner.innerHTML = '';
  const text = document.createElement('span');
  text.textContent = "Payment received. If features haven't unlocked, refresh the page.";
  const refreshBtn = document.createElement('button');
  refreshBtn.type = 'button';
  refreshBtn.textContent = 'Refresh';
  Object.assign(refreshBtn.style, {
    background: '#fff',
    color: '#16a34a',
    border: 'none',
    borderRadius: '4px',
    padding: '4px 12px',
    fontWeight: '600',
    fontSize: '12px',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  });
  refreshBtn.addEventListener('click', () => window.location.reload());
  banner.appendChild(text);
  banner.appendChild(refreshBtn);
}

function dismissBanner(banner: HTMLElement): void {
  banner.style.transform = 'translateY(-100%)';
  banner.style.opacity = '0';
  setTimeout(() => banner.remove(), 400);
}