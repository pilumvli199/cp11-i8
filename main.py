#!/usr/bin/env python3
"""
main.py - Phase1 LTP alerts with API-Key-aware REST headers

Changes:
- Adds X-PrivateKey (SMARTAPI_API_KEY) and X-SourceID/X-UserType headers to REST requests.
- Sends clearer Telegram diagnostics when API Key is invalid.
- Rest of Phase1 logic: single startup login, resolve instruments, poll LTP every POLL_INTERVAL and send Telegram messages.
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
SMARTAPI_API_KEY = os.getenv("SMARTAPI_API_KEY", "").strip()  # <-- ensure this is correct
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

INSTRUMENTS = {
    "NIFTY50":   {"exchange": "NSE", "symbol": "NIFTY 50",  "token": None},
    "BANKNIFTY": {"exchange": "NSE", "symbol": "BANKNIFTY",  "token": None},
    "SENSEX":    {"exchange": "BSE", "symbol": "SENSEX",     "token": None},
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

# Helper to build API headers including API key
def api_headers(jwt_token=None):
    headers = {"Content-Type": "application/json", "X-SourceID": "WEB", "X-UserType": "USER"}
    if SMARTAPI_API_KEY:
        headers["X-PrivateKey"] = SMARTAPI_API_KEY
    if jwt_token:
        headers["Authorization"] = f"Bearer {jwt_token}"
    return headers

# Instruments resolve
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
    wanted_map = {"NIFTY 50":"NIFTY50","NIFTY50":"NIFTY50","BANKNIFTY":"BANKNIFTY","BANK NIFTY":"BANKNIFTY","SENSEX":"SENSEX","S&P BSE SENSEX":"SENSEX"}
    found = {}
    for row in rows:
        try:
            trad_sym = (row.get("symbol") or row.get("tradingsymbol") or "").strip()
            exch = (row.get("exchange") or row.get("exch") or "").strip()
            token = row.get("token") or row.get("instrument_token") or row.get("symboltoken")
            if token is None:
                for k,v in row.items():
                    if "token" in str(k).lower():
                        token = v
                        break
            if not trad_sym or not token:
                continue
            key = None
            if trad_sym in wanted_map:
                key = wanted_map[trad_sym]
            else:
                for candidate,mapped in wanted_map.items():
                    if candidate.lower() in trad_sym.lower():
                        key = mapped
                        break
            if key and key not in found:
                found[key] = {"exchange": exch, "symbol": trad_sym, "token": str(token)}
        except Exception:
            continue

    for k,v in found.items():
        INSTRUMENTS[k]["exchange"] = v.get("exchange", INSTRUMENTS[k].get("exchange"))
        INSTRUMENTS[k]["symbol"] = v.get("symbol", INSTRUMENTS[k].get("symbol"))
        INSTRUMENTS[k]["token"] = v.get("token")
    logger.info("Instruments after resolve: %s", {k:INSTRUMENTS[k]["token"] for k in INSTRUMENTS})
    return found

# REST LTP attempts (with API key header)
def rest_ltp_order_service(token, exchange, jwt_token):
    try:
        url = BASE_API_HOST.rstrip("/") + "/order-service/rest/secure/angelbroking/order/v1/getLtpData"
        headers = api_headers(jwt_token)
        body = [{"exchange": exchange, "symboltoken": str(token)}]
        r = requests.post(url, headers=headers, json=body, timeout=8)
        return r.status_code, r.text[:4000]
    except Exception as e:
        return None, f"EXC: {e}"

def rest_ltp_marketdata(token, exchange, jwt_token):
    try:
        path = f"/rest/marketdata/ltp/v1?exchange={exchange}&symboltoken={token}" if exchange else f"/rest/marketdata/ltp/v1?symboltoken={token}"
        url = BASE_API_HOST.rstrip("/") + path
        headers = api_headers(jwt_token)
        r = requests.get(url, headers=headers, timeout=8)
        return r.status_code, r.text[:4000]
    except Exception as e:
        return None, f"EXC: {e}"

def get_ltp(info, jwt_token=None):
    # SDK attempts
    try:
        if hasattr(s, "getLtp"):
            return s.getLtp(info)
        if hasattr(s, "get_ltp"):
            return s.get_ltp(info)
        if hasattr(s, "getLtpData"):
            return s.getLtpData([info])
    except Exception:
        logger.debug("SDK get_ltp failed", exc_info=True)

    # REST attempts (with API key header)
    if not jwt_token:
        logger.debug("No JWT for REST LTP fallback")
        return None

    token = info.get("token") if isinstance(info, dict) else info
    exchange = info.get("exchange") if isinstance(info, dict) else ""

    st, body = rest_ltp_order_service(token, exchange, jwt_token)
    logger.debug("order-service attempt status=%s body[:300]=%s", st, body[:300])
    try:
        if st and st >= 200 and "{" in body:
            parsed = json.loads(body)
            # detect invalid API Key in response
            if isinstance(parsed, dict) and parsed.get("message") and "Invalid API Key" in str(parsed.get("message")):
                telegram_send_text("❌ REST returned Invalid API Key. Check SMARTAPI_API_KEY in .env.")
            return parsed
    except Exception:
        logger.debug("order-service parse failed", exc_info=True)

    st2, body2 = rest_ltp_marketdata(token, exchange, jwt_token)
    logger.debug("marketdata attempt status=%s body[:300]=%s", st2, body2[:300])
    try:
        if st2 and st2 >= 200 and "{" in body2:
            parsed2 = json.loads(body2)
            if isinstance(parsed2, dict) and parsed2.get("message") and "Invalid API Key" in str(parsed2.get("message")):
                telegram_send_text("❌ REST returned Invalid API Key. Check SMARTAPI_API_KEY in .env.")
            return parsed2
    except Exception:
        logger.debug("marketdata parse failed", exc_info=True)

    logger.warning("All REST LTP attempts failed for token=%s (status1=%s status2=%s)", token, st, st2)
    return None

def extract_ltp_from_response(resp):
    try:
        if resp is None:
            return None
        if isinstance(resp, (int, float, str)):
            try:
                return float(resp)
            except Exception:
                return None
        if isinstance(resp, dict):
            data = resp.get("data") or resp.get("result") or resp.get("ltp")
            if isinstance(data, dict):
                for k in ("lastPrice","lp","LTP","ltp"):
                    if k in data:
                        try:
                            return float(data[k])
                        except Exception:
                            pass
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                if isinstance(first, dict):
                    for k in ("lastPrice","lp","LTP","ltp"):
                        if k in first:
                            try:
                                return float(first[k])
                            except Exception:
                                pass
                else:
                    try:
                        return float(first)
                    except Exception:
                        pass
            for k in ("lastPrice","lp","LTP","ltp"):
                if k in resp:
                    try:
                        return float(resp[k])
                    except Exception:
                        pass
        return None
    except Exception:
        logger.exception("extract_ltp_from_response failed")
        return None

# Poll loop
def poll_ltp_loop(jwt_token):
    if not jwt_token:
        logger.error("No JWT token; aborting poll loop")
        return

    try:
        monitoring_list = ", ".join(list(INSTRUMENTS.keys()))
        telegram_send_text(f"📡 Bot online — Phase1 LTP alerts. Monitoring: {monitoring_list}\nPoll interval: {POLL_INTERVAL}s")
    except Exception:
        pass

    prev_ltps = {k: None for k in INSTRUMENTS.keys()}
    while True:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        logger.info("Polling LTP at %s", ts)
        for name, info in INSTRUMENTS.items():
            try:
                if not info.get("token"):
                    logger.warning("%s token missing - skipping", name)
                    telegram_send_text(f"{name}\nSignal: NO_DATA\n{name}: token missing - could not fetch LTP")
                    continue

                resp = get_ltp(info, jwt_token)
                ltp = extract_ltp_from_response(resp)
                prev = prev_ltps.get(name)
                if ltp is None:
                    resp_excerpt = str(resp)[:400] if resp is not None else "None"
                    # special handling: invalid API key message -> instruct user
                    if isinstance(resp, dict) and resp.get("message") and "Invalid API Key" in str(resp.get("message")):
                        telegram_send_text(f"❌ {name}: REST response indicates Invalid API Key. Please set SMARTAPI_API_KEY in .env to your AngelOne Private/API key and redeploy.")
                        logger.error("Invalid API Key detected in REST response")
                    else:
                        telegram_send_text(f"<b>{name}</b>\nSignal: NO_DATA\n{name}: Could not retrieve LTP (resp excerpt: {resp_excerpt})")
                        logger.warning("%s: LTP None (resp=%s)", name, resp_excerpt)
                else:
                    delta = None
                    pct = None
                    if prev is not None:
                        try:
                            delta = ltp - prev
                            pct = (delta / prev) * 100.0 if prev != 0 else 0.0
                        except Exception:
                            delta = None
                            pct = None
                    prev_ltps[name] = ltp
                    lines = [f"<b>{name}</b>", f"Time: {ts}", f"LTP: {ltp:.2f}"]
                    if delta is not None:
                        sign = "+" if delta > 0 else ""
                        lines.append(f"Δ: {sign}{delta:.2f} ({sign}{pct:.2f}%) vs prev")
                    else:
                        lines.append("Δ: (no previous)")
                    lines.append(f"Token: {info.get('token')}")
                    telegram_send_text("\n".join(lines))
                    logger.info("%s: sent LTP %s", name, ltp)
                time.sleep(0.3)
            except Exception:
                logger.exception("Error during LTP poll for %s", name)
        logger.info("Cycle complete; sleeping %s seconds", POLL_INTERVAL)
        time.sleep(POLL_INTERVAL)

# Main
if __name__ == "__main__":
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram vars missing; alerts will not be sent")

    # resolve instruments
    try:
        resolved = resolve_instruments_from_master()
        if resolved:
            try:
                telegram_send_text("Instrument tokens auto-resolved:\n" + "\n".join([f"{k}: {INSTRUMENTS[k]['token']}" for k in INSTRUMENTS]))
            except Exception:
                pass
        else:
            logger.info("No instruments auto-resolved; tokens may need manual set")
    except Exception:
        logger.exception("resolve_instruments_from_master failed")

    # login
    resp, jwt_token = login()
    if not resp or not jwt_token:
        logger.error("Startup login failed. Check credentials and TOTP. Exiting.")
        sys.exit(1)

    # start loop
    poll_ltp_loop(jwt_token)
