# payment_webhook.py
"""
FastAPI webhook server for top-ups via Stripe only (no local utils dependency).

This service calls your main backend over HTTP for:
- Creating top-up records and TxID
- Marking a TxID as paid when Stripe webhook succeeds

Internal API contracts (implement on main backend):
- POST {BACKEND_BASE_URL}/internal/topups/request
  Payload JSON: {
    "user": {"Username": "-"},
    "amount": <float THB>,
    "method": "Stripe/Checkout",
    "description": "Top-up"  // optional
  }
  Response JSON: { "TxID": "XXXXXX" } or { "txid": "XXXXXX" }

- POST {BACKEND_BASE_URL}/internal/topups/mark-paid
  Payload JSON: {
    "txid": "XXXXXX",
    "amount": <float THB | null>,  // can be null if not known
    "provider": "Stripe",
    "provider_txn_id": "pi_xxx or ch_xxx"
  }
  Response JSON: { "ok": true }  (treat any non-2xx or ok!=true as failure)

Required env:
  STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET
  BACKEND_BASE_URL, INTERNAL_AUTH_SECRET  // for calling main backend

Optional env:
  STRIPE_SUCCESS_URL, STRIPE_CANCEL_URL
  ALLOWED_CURRENCIES (default "thb")
  MIN_TOPUP_THB (default 20.0), MAX_TOPUP_THB (default 50000.0)
  STRICT_AMOUNT_MATCH (default true), ON_MISMATCH (log_only|reject; default log_only)
  CORS_ALLOW_ORIGINS (comma list)
  EVENT_STORE_BACKEND (sqlite|memory; default sqlite)
  HTTP_TIMEOUT_SEC (default 10)

Run:
  uvicorn payment_webhook:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import os
import hmac
import json
import hashlib
import logging
import sqlite3
from uuid import uuid4
from typing import Any, Dict, Optional, Tuple

import requests
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("payment_webhook")

# -----------------------------------------------------------------------------
# App & Static
# -----------------------------------------------------------------------------
app = FastAPI(title="Payments Webhook + Top-up")

web_dir = os.path.join(os.path.dirname(__file__), "web")
if os.path.isdir(web_dir):
    app.mount("/web", StaticFiles(directory=web_dir), name="web")

@app.get("/topup")
async def topup_page():
    index_path = os.path.join(web_dir, "topup.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return JSONResponse({"error": "topup page not found"}, status_code=404)

# -----------------------------------------------------------------------------
# CORS (optional)
# -----------------------------------------------------------------------------
_allow = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
if _allow:
    origins = [o.strip() for o in _allow.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    log.info("CORS enabled for: %s", origins)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _getenv_str(key: str) -> Optional[str]:
    v = os.getenv(key)
    return v if v else None

def _bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name, str(default)).strip().lower()
    return v in {"1", "true", "yes", "y"}

def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except Exception:
        return default

def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except Exception:
        return default

# -----------------------------------------------------------------------------
# Idempotency store (sqlite default; memory fallback)
# -----------------------------------------------------------------------------
class EventStore:
    def exists(self, provider: str, event_id: str) -> bool: ...
    def save(self, provider: str, event_id: str) -> None: ...

class SqliteEventStore(EventStore):
    def __init__(self, path: str = "events.db"):
        self.path = path
        self._ensure()

    def _ensure(self):
        con = sqlite3.connect(self.path)
        try:
            con.execute(
                "CREATE TABLE IF NOT EXISTS processed (provider TEXT NOT NULL, event_id TEXT NOT NULL, ts INTEGER DEFAULT (strftime('%s','now')), PRIMARY KEY(provider, event_id))"
            )
            con.commit()
        finally:
            con.close()

    def exists(self, provider: str, event_id: str) -> bool:
        con = sqlite3.connect(self.path)
        try:
            cur = con.execute("SELECT 1 FROM processed WHERE provider=? AND event_id=? LIMIT 1", (provider, event_id))
            return cur.fetchone() is not None
        finally:
            con.close()

    def save(self, provider: str, event_id: str) -> None:
        con = sqlite3.connect(self.path)
        try:
            con.execute("INSERT OR IGNORE INTO processed(provider, event_id) VALUES(?,?)", (provider, event_id))
            con.commit()
        finally:
            con.close()

class MemoryEventStore(EventStore):
    def __init__(self):
        self._seen = set()

    def exists(self, provider: str, event_id: str) -> bool:
        return (provider, event_id) in self._seen

    def save(self, provider: str, event_id: str) -> None:
        self._seen.add((provider, event_id))

_store_backend = os.getenv("EVENT_STORE_BACKEND", "sqlite").strip().lower()
try:
    event_store: EventStore = SqliteEventStore() if _store_backend == "sqlite" else MemoryEventStore()
    log.info("Event store backend: %s", _store_backend)
except Exception as e:
    log.warning("Event store init failed (%s), falling back to memory", e)
    event_store = MemoryEventStore()

# -----------------------------------------------------------------------------
# Internal backend HTTP client (no local utils)
# -----------------------------------------------------------------------------
_BACKEND_BASE_URL = (os.getenv("BACKEND_BASE_URL", "").rstrip("/"))
_INTERNAL_AUTH_SECRET = os.getenv("INTERNAL_AUTH_SECRET", "")
_HTTP_TIMEOUT = _int_env("HTTP_TIMEOUT_SEC", 10)

if not _BACKEND_BASE_URL:
    log.warning("BACKEND_BASE_URL not set; will fallback to local TxID if needed")
if not _INTERNAL_AUTH_SECRET:
    log.warning("INTERNAL_AUTH_SECRET not set; calls to backend will likely be unauthorized")


def _auth_headers() -> Dict[str, str]:
    h = {"Content-Type": "application/json"}
    if _INTERNAL_AUTH_SECRET:
        h["X-Internal-Auth"] = _INTERNAL_AUTH_SECRET
    return h


def backend_record_topup_request(user: Dict[str, Any], amount_baht: float, method: str, description: str) -> Optional[str]:
    if not _BACKEND_BASE_URL:
        return None
    try:
        url = f"{_BACKEND_BASE_URL}/internal/topups/request"
        payload = {
            "user": user,
            "amount": float(amount_baht),
            "method": method,
            "description": description,
        }
        resp = requests.post(url, data=json.dumps(payload), headers=_auth_headers(), timeout=_HTTP_TIMEOUT)
        if resp.status_code >= 400:
            log.warning("record_topup_request backend error: %s %s", resp.status_code, resp.text[:500])
            return None
        data = resp.json() if resp.content else {}
        txid = str(data.get("TxID") or data.get("txid") or "").strip()
        return txid or None
    except Exception as e:
        log.warning("record_topup_request call failed: %s", e)
        return None


def backend_update_topup_status_paid(txid: str, amount_baht: Optional[float], provider: str, provider_txn_id: str) -> bool:
    if not _BACKEND_BASE_URL:
        return False
    try:
        url = f"{_BACKEND_BASE_URL}/internal/topups/mark-paid"
        payload = {
            "txid": txid,
            "amount": (None if amount_baht is None else float(amount_baht)),
            "provider": provider,
            "provider_txn_id": provider_txn_id,
        }
        resp = requests.post(url, data=json.dumps(payload), headers=_auth_headers(), timeout=_HTTP_TIMEOUT)
        if resp.status_code >= 400:
            log.warning("mark-paid backend error: %s %s", resp.status_code, resp.text[:500])
            return False
        data = resp.json() if resp.content else {}
        return bool(data.get("ok", True))
    except Exception as e:
        log.warning("mark-paid call failed: %s", e)
        return False

# -----------------------------------------------------------------------------
# Stripe publishable key (for frontend)
# -----------------------------------------------------------------------------
@app.get("/api/stripe-pubkey")
async def stripe_pubkey():
    pk = _getenv_str("STRIPE_PUBLISHABLE_KEY")
    return {"publishableKey": pk}

# -----------------------------------------------------------------------------
# Stripe: create Checkout Session (variable amount top-up)
# -----------------------------------------------------------------------------
@app.post("/api/stripe/create-checkout-session")
async def stripe_create_checkout_session(request: Request):
    """
    Expects JSON:
      { "amount": <int minor units>, "currency": "thb", "description": "Top-up" }
    """
    body = await request.json()
    # amount (minor units)
    try:
        amount_minor = int(body.get("amount") or 0)
    except Exception:
        raise HTTPException(status_code=400, detail="amount must be integer minor units")

    currency = str(body.get("currency") or "").lower() or "thb"
    description = str(body.get("description") or "Top-up")

    # Safety: whitelist currency + min/max range
    allowed = {c.strip().lower() for c in os.getenv("ALLOWED_CURRENCIES", "thb").split(",")}
    if currency not in allowed:
        raise HTTPException(status_code=400, detail="unsupported currency")

    min_thb = _float_env("MIN_TOPUP_THB", 20.0)
    max_thb = _float_env("MAX_TOPUP_THB", 50000.0)
    min_minor = int(round(min_thb * 100))
    max_minor = int(round(max_thb * 100))

    if amount_minor <= 0:
        raise HTTPException(status_code=400, detail="amount must be > 0")
    if not (min_minor <= amount_minor <= max_minor):
        raise HTTPException(status_code=400, detail=f"amount out of bounds ({min_thb}-{max_thb} THB)")

    # Create TxID via backend & record expected amount
    txid: Optional[str] = None
    try:
        txid = backend_record_topup_request({"Username": "-"}, amount_minor / 100.0, "Stripe/Checkout", description)
    except Exception:
        txid = None
    if not txid:
        # Fallback TxID if backend not reachable
        txid = str(uuid4())[:8].upper()

    secret_key = _getenv_str("STRIPE_SECRET_KEY")
    if not secret_key:
        raise HTTPException(status_code=500, detail="Missing STRIPE_SECRET_KEY")

    success_url = os.getenv("STRIPE_SUCCESS_URL", "http://localhost:8080/topup?status=success&sid={CHECKOUT_SESSION_ID}")
    cancel_url  = os.getenv("STRIPE_CANCEL_URL",  "http://localhost:8080/topup?status=cancel")

    # server-truth metadata for webhook strict checking
    metadata = {
        "txid": txid,
        "expected_amount_minor": str(amount_minor),
        "expected_currency": currency,
        "origin": "server",
    }

    session_id: Optional[str] = None
    session_url: Optional[str] = None

    # Prefer Stripe SDK
    try:
        import stripe  # type: ignore
        stripe.api_key = secret_key
        session = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": currency,
                    "product_data": {"name": description},
                    "unit_amount": amount_minor,
                },
                "quantity": 1,
            }],
            metadata=metadata,
            payment_intent_data={"metadata": metadata},
            success_url=success_url,
            cancel_url=cancel_url,
        )
        session_id = session.get("id")
        session_url = session.get("url")
    except Exception as e:
        # Fallback REST
        log.warning("Stripe SDK failed (%s), using REST fallback", e)
        url = "https://api.stripe.com/v1/checkout/sessions"
        data = {
            "mode": "payment",
            "payment_method_types[]": "card",
            "success_url": success_url,
            "cancel_url": cancel_url,
            "line_items[0][price_data][currency]": currency,
            "line_items[0][price_data][product_data][name]": description,
            "line_items[0][price_data][unit_amount]": str(amount_minor),
            "line_items[0][quantity]": "1",
            "metadata[txid]": metadata["txid"],
            "metadata[expected_amount_minor]": metadata["expected_amount_minor"],
            "metadata[expected_currency]": metadata["expected_currency"],
            "metadata[origin]": "server",
            "payment_intent_data[metadata][txid]": metadata["txid"],
            "payment_intent_data[metadata][expected_amount_minor]": metadata["expected_amount_minor"],
            "payment_intent_data[metadata][expected_currency]": metadata["expected_currency"],
            "payment_intent_data[metadata][origin]": "server",
        }
        resp = requests.post(url, data=data, auth=(secret_key, ""), timeout=_HTTP_TIMEOUT)
        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        j = resp.json()
        session_id = j.get("id")
        session_url = j.get("url")

    return {"sessionId": session_id, "txid": txid, "url": session_url}

# -----------------------------------------------------------------------------
# Stripe Webhook
# -----------------------------------------------------------------------------

def _extract_from_session(obj: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], str, str]:
    txid = (obj.get("metadata") or {}).get("txid")
    amount_minor = obj.get("amount_total") or obj.get("amount_subtotal")
    currency = (obj.get("currency") or "thb").lower()
    provider_txn_id = str(obj.get("payment_intent") or obj.get("id") or "")
    try:
        amount_minor = int(amount_minor) if amount_minor is not None else None
    except Exception:
        amount_minor = None
    return txid, amount_minor, currency, provider_txn_id

def _extract_from_payment_intent(obj: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], str, str]:
    meta = obj.get("metadata") or {}
    txid = meta.get("txid")
    amount_minor = obj.get("amount_received") or obj.get("amount")
    currency = (obj.get("currency") or "thb").lower()
    provider_txn_id = str(obj.get("id") or "")
    try:
        amount_minor = int(amount_minor) if amount_minor is not None else None
    except Exception:
        amount_minor = None
    return txid, amount_minor, currency, provider_txn_id

def _extract_from_charge(obj: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], str, str]:
    meta = obj.get("metadata") or {}
    txid = meta.get("txid")
    amount_minor = obj.get("amount")
    currency = (obj.get("currency") or "thb").lower()
    provider_txn_id = str(obj.get("id") or "")
    try:
        amount_minor = int(amount_minor) if amount_minor is not None else None
    except Exception:
        amount_minor = None
    return txid, amount_minor, currency, provider_txn_id

@app.post("/webhook/stripe")
async def webhook_stripe(request: Request, background: BackgroundTasks):
    raw = await request.body()
    sig = request.headers.get("Stripe-Signature")
    secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not secret or not sig:
        raise HTTPException(status_code=400, detail="missing signature or secret")

    # Verify signature
    try:
        import stripe  # type: ignore
        evt = stripe.Webhook.construct_event(payload=raw, sig_header=sig, secret=secret)  # type: ignore
    except Exception:
        try:
            parts = dict(kv.split("=", 1) for kv in (sig or "").split(","))
            ts = parts.get("t")
            v1 = parts.get("v1")
            if not ts or not v1:
                raise ValueError("bad signature header")
            signed = (ts + "." + raw.decode("utf-8")).encode("utf-8")
            mac = hmac.new(secret.encode("utf-8"), msg=signed, digestmod=hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, v1):
                raise ValueError("invalid signature")
            evt = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"signature verify failed: {e}")

    # Idempotency (avoid double credit)
    event_id = str(evt.get("id") or "")
    if event_id:
        if event_store.exists("stripe", event_id):
            return JSONResponse({"ok": True, "duplicate": True})
        event_store.save("stripe", event_id)

    etype = evt.get("type")
    obj = (evt.get("data") or {}).get("object") or {}

    txid: Optional[str] = None
    amount_minor: Optional[int] = None
    currency = "thb"
    provider_txn_id = ""

    if etype and etype.startswith("checkout.session."):
        txid, amount_minor, currency, provider_txn_id = _extract_from_session(obj)
    elif etype and etype.startswith("payment_intent."):
        txid, amount_minor, currency, provider_txn_id = _extract_from_payment_intent(obj)
    elif etype and etype.startswith("charge."):
        txid, amount_minor, currency, provider_txn_id = _extract_from_charge(obj)
    else:
        return JSONResponse({"ok": True, "ignored": True})

    if not txid:
        return JSONResponse({"ok": True, "ignored": True})

    # Strict compare against expected (if provided)
    strict = _bool_env("STRICT_AMOUNT_MATCH", True)
    on_mismatch = os.getenv("ON_MISMATCH", "log_only").strip().lower()  # log_only | reject
    expected_minor = None
    try:
        expected_minor = int((obj.get("metadata") or {}).get("expected_amount_minor"))
    except Exception:
        expected_minor = None

    if strict and (expected_minor is not None) and (amount_minor is not None) and (expected_minor != amount_minor):
        msg = f"amount mismatch: expected={expected_minor} got={amount_minor} (txid={txid})"
        if on_mismatch == "reject":
            log.warning("REJECT %s", msg)
            return JSONResponse({"ok": False, "reason": "amount_mismatch"}, status_code=200)
        else:
            log.warning("LOG_ONLY %s", msg)

    # Convert to baht
    amount_baht: Optional[float] = None
    if amount_minor is not None:
        try:
            amount_baht = float(amount_minor) / 100.0
        except Exception:
            amount_baht = None

    # Do update in background via backend
    def _apply():
        try:
            ok = backend_update_topup_status_paid(
                txid=str(txid),
                amount_baht=amount_baht,
                provider="Stripe",
                provider_txn_id=provider_txn_id,
            )
            if not ok:
                log.warning("backend_update_topup_status_paid returned False (txid=%s)", txid)
        except Exception as e:
            log.exception("backend_update_topup_status_paid error: %s", e)

    background.add_task(_apply)
    return {"ok": True}
