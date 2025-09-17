#!/usr/bin/env python3
"""
main.py — indices-first + stocks-fallback LTP poller (Phase1 enhanced)

Behavior:
- Resolve tokens from master and merge with built-in fallbacks.
- For each instrument (indices first), try tokens in order until one returns LTP.
- Use SDK first, then multiple REST endpoints with proper headers (X-PrivateKey).
- Send Telegram messages every POLL_INTERVAL seconds with LTP and Δ vs previous.
"""

import os
import sys
import time
import logging
import importlib
import traceback
import requests
import json
from dotenv import load_dotenv

load_dotenv()

# Logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(asctime)s %(message)s")
logger = logging.getLogger(__name__)

# ENV
SMARTAPI_API_KEY = os.getenv("SMARTAPI_API_KEY", "").strip()
SMARTAPI_CLIENT_CODE = os.getenv("SMARTAPI_CLIENT_CODE", "").strip()
SMARTAPI_MPIN = os.getenv("SMARTAPI_MPIN", "").strip()
SMARTAPI_PASSWORD = os.getenv("SMARTAPI_PASSWORD", "").strip()
SMARTAPI_TOTP_SECRET = os.getenv("SMARTAPI_TOTP_SECRET", "").strip()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

POLL_INTERVAL = int(os.getenv("MARKET_POLL_INTERVAL_SECONDS", "60"))

INSTRUMENTS_URL = os.getenv(
    "INSTRUMENTS_URL",
    "https://margincalculator.angelone.in/OpenAPI_File/files/OpenAPIScripMaster.json"
)
BASE_API_HOST = os.getenv("SMARTAPI_BASE_URL", "https://apiconnect.angelone.in")

# Instruments list: indices first (tokens may be placeholders) + stocks fallback
INSTRUMENTS = {
    # INDICES (try these tokens first; some envs/APIs may reject index endpoints)
    "NIFTY50": {
        "exchange": "NSE",
        "symbol": "NIFTY 50",
        # common fallback tokens (try these; replace if you have correct tokens)
        "tokens": ["99926000", "256265", "999260"],  
        "trading_symbols": ["NIFTY 50", "NIFTY", "NIFTY50"]
    },
    "BANKNIFTY": {
        "exchange": "NSE",
        "symbol": "BANKNIFTY",
        "tokens": ["99926009", "BANKNIFTY-INDEX-TOKEN"], 
        "trading_symbols": ["BANKNIFTY", "BANK NIFTY"]
    },
    "SENSEX": {
        "exchange": "BSE",
        "symbol": "SENSEX",
        "tokens": ["99919000", "1"],  # try both common guesses
        "trading_symbols": ["SENSEX", "S&P BSE SENSEX"]
    },

    # MAJOR STOCKS (fallbacks / representatives)
    "RELIANCE": {
        "exchange": "NSE",
        "symbol": "RELIANCE",
        "tokens": ["2885"],
        "trading_symbols": ["RELIANCE", "RELIANCE-EQ"]
    },
    "HDFCBANK": {
        "exchange": "NSE",
        "symbol": "HDFCBANK",
        "tokens": ["1333"],
        "trading_symbols": ["HDFCBANK", "HDFCBANK-EQ"]
    },
    "INFY": {
        "exchange": "NSE",
        "symbol": "INFY",
        "tokens": ["1594"],
        "trading_symbols": ["INFY", "INFY-EQ"]
    },
    "TCS": {
        "exchange": "NSE",
        "symbol": "TCS",
        "tokens": ["11536"],
        "trading_symbols": ["TCS", "TCS-EQ"]
    },
    "ITC": {
        "exchange": "NSE",
        "symbol": "ITC",
        "tokens": ["1660"],
        "trading_symbols": ["ITC", "ITC-EQ"]
    }
}

# Import SmartConnect
SmartConnect = None
for candidate in ("smartapi", "SmartApi", "smartapi_python"):
    try:
        mod = importlib.import_module(candidate)
        if hasattr(mod, "SmartConnect"):
            SmartConnect = getattr(mod, "SmartConnect")
            logger.info("Using SmartConnect from module '%s'", candidate)
            break
        if hasattr(mod, "smartConnect") and hasattr(mod.smartConnect, "SmartConnect"):
            SmartConnect = getattr(mod.smartConnect, "SmartConnect")
            logger.info("Using SmartConnect from submodule '%s.smartConnect'", candidate)
            break
    except Exception:
        continue

if SmartConnect is None:
    logger.error("SmartConnect import failed. Install 'smartapi-python'.")
    sys.exit(1)

# instantiate SmartConnect
try:
    try:
        s = SmartConnect(api_key=SMARTAPI_API_KEY)
    except TypeError:
        s = SmartConnect(SMARTAPI_API_KEY)
except Exception:
    logger.exception("SmartConnect init failed")
    sys.exit(1)

# optional pyotp
try:
    import pyotp
except Exception:
    pyotp = None

def totp_now(secret):
    if not pyotp or not secret:
        return None
    try:
        return pyotp.TOTP(secret).now()
    except Exception:
        logger.exception("TOTP generation failed")
        return None

def _extract_jwt_from_resp(resp):
    try:
        if not resp or not isinstance(resp, dict):
            return None
        data = resp.get("data") or {}
        jwt = data.get("jwtToken") or data.get("token") or data.get("jwt")
        if isinstance(jwt, str) and jwt.startswith("Bearer "):
            return jwt.split(" ", 1)[1]
        return jwt
    except Exception:
        return None

def login():
    """Try MPIN+TOTP first, then password fallback."""
    if SMARTAPI_MPIN and SMARTAPI_TOTP_SECRET:
        code = totp_now(SMARTAPI_TOTP_SECRET)
        try:
            logger.info("Attempting MPIN+TOTP login")
            resp = s.generateSession(SMARTAPI_CLIENT_CODE, SMARTAPI_MPIN, code)
            jwt = _extract_jwt_from_resp(resp)
            logger.info("Login status=%s message=%s", resp.get("status"), resp.get("message"))
            return resp, jwt
        except Exception as e:
            logger.warning("MPIN login exception: %s", e)
            logger.debug(traceback.format_exc())
    if SMARTAPI_PASSWORD and SMARTAPI_TOTP_SECRET:
        code = totp_now(SMARTAPI_TOTP_SECRET)
        try:
            logger.info("Attempting Password+TOTP login (fallback)")
            resp = s.generateSession(SMARTAPI_CLIENT_CODE, SMARTAPI_PASSWORD, code)
            jwt = _extract_jwt_from_resp(resp)
            logger.info("Login status=%s message=%s", resp.get("status"), resp.get("message"))
            return resp, jwt
        except Exception as e:
            logger.warning("Password login exception: %s", e)
            logger.debug(traceback.format_exc())
    logger.error("No valid credentials for login found.")
    return None, None

# Telegram helper
def telegram_send_text(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram creds missing; skipping telegram_send_text")
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()
        return True
    except Exception:
        logger.exception("telegram_send_text failed")
        return False

# Headers builder (include X-PrivateKey)
def api_headers(jwt_token=None):
    headers = {"Content-Type": "application/json", "X-SourceID": "WEB", "X-UserType": "USER"}
    if SMARTAPI_API_KEY:
        headers["X-PrivateKey"] = SMARTAPI_API_KEY
    if jwt_token:
        headers["Authorization"] = f"Bearer {jwt_token}"
    return headers

# REST endpoints
def rest_post_json(path, body, jwt_token):
    try:
        url = BASE_API_HOST.rstrip("/") + path
        headers = api_headers(jwt_token)
        r = requests.post(url, headers=headers, json=body, timeout=8)
        if r.status_code == 200:
            try:
                return r.status_code, r.json()
            except Exception:
                return r.status_code, r.text
        return r.status_code, r.text
    except Exception as e:
        return None, f"EXC:{e}"

def rest_get(path, jwt_token):
    try:
        url = BASE_API_HOST.rstrip("/") + path
        headers = api_headers(jwt_token)
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code == 200:
            try:
                return r.status_code, r.json()
            except Exception:
                return r.status_code, r.text
        return r.status_code, r.text
    except Exception as e:
        return None, f"EXC:{e}"

# LTP attempt helpers (order-service, marketdata, alternative)
def rest_ltp_order_service(token, exchange, jwt_token):
    body = [{"exchange": exchange, "symboltoken": str(token)}]
    return rest_post_json("/order-service/rest/secure/angelbroking/order/v1/getLtpData", body, jwt_token)

def rest_ltp_marketdata(token, exchange, jwt_token):
    path = f"/rest/marketdata/ltp/v1?exchange={exchange}&symboltoken={token}" if exchange else f"/rest/marketdata/ltp/v1?symboltoken={token}"
    return rest_get(path, jwt_token)

def rest_ltp_alt(token, exchange, jwt_token):
    body = {"exchange": exchange, "symboltoken": str(token)}
    return rest_post_json("/rest/secure/angelbroking/user/v1/getLtp", body, jwt_token)

# Extract LTP from varied responses
def extract_ltp_from_response(resp):
    try:
        if resp is None:
            return None
        if isinstance(resp, (int, float)):
            return float(resp)
        if isinstance(resp, str):
            try:
                return float(resp)
            except Exception:
                return None
        if isinstance(resp, dict):
            # check message for API key errors
            msg = resp.get("message") or resp.get("statusMessage") or ""
            if isinstance(msg, str) and "Invalid API Key" in msg:
                return {"error": "invalid_api_key", "raw": resp}
            data = resp.get("data") or resp.get("result") or resp.get("ltp")
            if isinstance(data, dict):
                for f in ("ltp", "lastPrice", "lp", "close"):
                    if f in data:
                        try:
                            return float(data[f])
                        except: pass
            if isinstance(data, list) and data:
                first = data[0]
                if isinstance(first, dict):
                    for f in ("ltp", "lastPrice", "lp", "close"):
                        if f in first:
                            try:
                                return float(first[f])
                            except: pass
                else:
                    try: return float(first)
                    except: pass
            for f in ("ltp", "lastPrice", "lp", "close"):
                if f in resp:
                    try:
                        return float(resp[f])
                    except: pass
        return None
    except Exception:
        logger.exception("extract_ltp_from_response failed")
        return None

# Try tokens in order for an instrument
def get_ltp_for_instrument(inst_name, inst_cfg, jwt_token):
    exchange = inst_cfg.get("exchange", "")
    tokens = inst_cfg.get("tokens", []) or []
    if not tokens:
        return None, "no_tokens"

    # Keep details of failures for diagnostics
    failures = []
    for idx, token in enumerate(tokens):
        logger.info("%s: Trying token %s (%d/%d)", inst_name, token, idx+1, len(tokens))
        info = {"exchange": exchange, "symboltoken": str(token)}
        # SDK attempt
        try:
            if hasattr(s, "getLtp"):
                sdk_resp = s.getLtp(info)
                l = extract_ltp_from_response(sdk_resp)
                if isinstance(l, dict) and l.get("error") == "invalid_api_key":
                    return None, "invalid_api_key"
                if l is not None:
                    return l, f"sdk:token_{token}"
        except Exception as e:
            logger.debug("%s: SDK attempt failed for token %s -> %s", inst_name, token, e)

        # REST attempts (order-service)
        if jwt_token:
            st, resp = rest_ltp_order_service(token, exchange, jwt_token)
            if isinstance(resp, dict) and resp.get("message") and "Invalid API Key" in str(resp.get("message")):
                return None, "invalid_api_key"
            l = extract_ltp_from_response(resp) if isinstance(resp, dict) else None
            if l is not None:
                return l, f"order-service:token_{token}"

            # marketdata GET
            st2, resp2 = rest_ltp_marketdata(token, exchange, jwt_token)
            if isinstance(resp2, dict) and resp2.get("message") and "Invalid API Key" in str(resp2.get("message")):
                return None, "invalid_api_key"
            l2 = extract_ltp_from_response(resp2) if isinstance(resp2, dict) else None
            if l2 is not None:
                return l2, f"marketdata:token_{token}"

            # alternative
            st3, resp3 = rest_ltp_alt(token, exchange, jwt_token)
            if isinstance(resp3, dict) and resp3.get("message") and "Invalid API Key" in str(resp3.get("message")):
                return None, "invalid_api_key"
            l3 = extract_ltp_from_response(resp3) if isinstance(resp3, dict) else None
            if l3 is not None:
                return l3, f"alt:token_{token}"

        # collect failure snippet
        failures.append({"token": token, "sdk": None})
    logger.warning("%s: All %d tokens exhausted, no LTP retrieved", inst_name, len(tokens))
    return None, f"all_{len(tokens)}_failed"

# Resolve instruments from master and augment tokens (best-effort)
def resolve_instruments_from_master():
    try:
        logger.info("Downloading instruments master: %s", INSTRUMENTS_URL)
        r = requests.get(INSTRUMENTS_URL, timeout=20)
        r.raise_for_status()
        data = r.json()
    except Exception:
        logger.exception("Failed to download instruments master")
        return {}

    rows = data if isinstance(data, list) else data.get("data", []) if isinstance(data, dict) else []
    for inst_name, inst_cfg in INSTRUMENTS.items():
        symbols = inst_cfg.get("trading_symbols", [inst_cfg.get("symbol")])
        exchange = inst_cfg.get("exchange", "")
        found = []
        for row in rows:
            try:
                trad = (row.get("symbol") or row.get("tradingsymbol") or "").strip()
                exch = (row.get("exchange") or row.get("exch") or "").strip()
                token = row.get("token") or row.get("instrument_token") or row.get("symboltoken")
                if not trad or not token:
                    continue
                if exch.upper() == exchange.upper():
                    for sname in symbols:
                        if sname and trad.upper() == sname.upper():
                            ts = str(token)
                            if ts not in found:
                                found.append(ts)
            except Exception:
                continue
        # merge found tokens with existing, keeping existing first
        merged = inst_cfg.get("tokens", [])[:]
        for t in found:
            if t not in merged:
                merged.append(t)
        INSTRUMENTS[inst_name]["tokens"] = merged
        logger.info("Final tokens for %s: %s", inst_name, merged)
    return INSTRUMENTS

# Poll loop
def poll_ltp_loop(jwt_token):
    if not jwt_token:
        logger.error("No JWT token; aborting poll loop")
        return

    try:
        monitoring_list = ", ".join(list(INSTRUMENTS.keys()))
        telegram_send_text(f"📡 Bot online — Indices-first LTP alerts\nMonitoring: {monitoring_list}\nPoll interval: {POLL_INTERVAL}s\n(Indices attempted first; stocks act as fallback)")
    except Exception:
        pass

    prev_ltps = {k: None for k in INSTRUMENTS.keys()}

    while True:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        logger.info("Polling LTP at %s", ts)
        successful = 0
        for name, cfg in INSTRUMENTS.items():
            try:
                ltp, method = get_ltp_for_instrument(name, cfg, jwt_token)
                prev = prev_ltps.get(name)
                # invalid API key shortcut
                if method == "invalid_api_key":
                    telegram_send_text(f"❌ <b>{name}</b>\nSignal: NO_DATA\nStatus: Invalid API Key detected in response. Please set SMARTAPI_API_KEY correctly in .env and redeploy.")
                    logger.error("Invalid API Key detected; aborting subsequent REST attempts")
                    continue

                if ltp is None:
                    telegram_send_text(f"❌ <b>{name}</b>\nSignal: NO_DATA\nStatus: {method}\nTime: {ts}")
                    logger.warning("%s: LTP None (%s)", name, method)
                else:
                    successful += 1
                    delta = None
                    pct = None
                    if prev is not None:
                        try:
                            delta = ltp - prev
                            pct = (delta / prev) * 100.0 if prev != 0 else 0.0
                        except:
                            delta = None
                            pct = None
                    prev_ltps[name] = ltp
                    lines = [f"✅ <b>{name}</b>", f"Time: {ts}", f"LTP: ₹{ltp:.2f}"]
                    if delta is not None:
                        sign = "+" if delta > 0 else ""
                        emoji = "📈" if delta > 0 else "📉" if delta < 0 else "➡️"
                        lines.append(f"Δ: {sign}{delta:.2f} ({sign}{pct:.2f}%) {emoji}")
                    else:
                        lines.append("Δ: (first reading)")
                    lines.append(f"Method: {method}")
                    telegram_send_text("\n".join(lines))
                    logger.info("%s: LTP sent (%s)", name, method)
                time.sleep(0.4)
            except Exception:
                logger.exception("Error during LTP poll for %s", name)
                telegram_send_text(f"❌ <b>{name}</b>\nSignal: ERROR\nTime: {ts}")
        logger.info("Cycle complete: %d/%d successful. Sleeping %ds", successful, len(INSTRUMENTS), POLL_INTERVAL)
        time.sleep(POLL_INTERVAL)

# Entrypoint
if __name__ == "__main__":
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram vars missing; alerts will not be sent")

    # 1) Resolve instruments (merge master tokens with fallback)
    try:
        resolve_instruments_from_master()
        token_summary = [f"{k}: {len(v.get('tokens',[]))} tokens {v.get('tokens',[])[:3]}" for k,v in INSTRUMENTS.items()]
        telegram_send_text("🔍 Instrument resolution done:\n" + "\n".join(token_summary))
    except Exception:
        logger.exception("resolve_instruments_from_master failed")

    # 2) Login
    resp, jwt_token = login()
    if not resp or not jwt_token:
        error_msg = "❌ Login failed! Check credentials and TOTP"
        logger.error(error_msg)
        telegram_send_text(error_msg)
        sys.exit(1)

    telegram_send_text("✅ Login successful! Starting LTP monitoring...")

    # 3) Start polling loop
    try:
        poll_ltp_loop(jwt_token)
    except KeyboardInterrupt:
        logger.info("Stopped by user")
        telegram_send_text("🛑 Bot stopped manually")
    except Exception:
        logger.exception("Fatal error in poll loop")
        telegram_send_text("💥 Bot crashed! Check logs")
        raise
