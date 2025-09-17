#!/usr/bin/env python3
"""
Enhanced main.py - Fixed Angel One LTP data fetching issues
Phase1: LTP-only alerts every POLL_INTERVAL seconds to Telegram.

WORKAROUND: Using major stocks instead of indices (Angel One index data is broken)

Replace your existing main.py with this file and deploy.
Ensure .env contains: SMARTAPI_CLIENT_CODE, SMARTAPI_MPIN (or SMARTAPI_PASSWORD),
SMARTAPI_TOTP_SECRET, SMARTAPI_API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
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

# WORKAROUND: Using major stocks instead of indices (Angel One index data is broken)
# These are confirmed working stocks that represent market movement
INSTRUMENTS = {
    "RELIANCE": {
        "exchange": "NSE", 
        "symbol": "RELIANCE",
        "tokens": ["2885"],  # Reliance Industries - major NIFTY component
        "trading_symbols": ["RELIANCE", "RELIANCE-EQ"]
    },
    "HDFCBANK": {
        "exchange": "NSE", 
        "symbol": "HDFCBANK",
        "tokens": ["1333"],  # HDFC Bank - major banking stock
        "trading_symbols": ["HDFCBANK", "HDFCBANK-EQ"]
    },
    "INFY": {
        "exchange": "NSE", 
        "symbol": "INFY",
        "tokens": ["1594"],  # Infosys - major IT stock
        "trading_symbols": ["INFY", "INFY-EQ"]
    },
    "TCS": {
        "exchange": "NSE", 
        "symbol": "TCS",
        "tokens": ["11536"],  # TCS - major IT stock
        "trading_symbols": ["TCS", "TCS-EQ"]
    },
    "ITC": {
        "exchange": "NSE", 
        "symbol": "ITC",
        "tokens": ["1660"],  # ITC - major FMCG stock
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

# Enhanced REST LTP attempts with better parsing
def rest_ltp_order_service(token, exchange, jwt_token):
    """POST /order-service/.../getLtpData with enhanced response parsing"""
    try:
        url = BASE_API_HOST.rstrip("/") + "/order-service/rest/secure/angelbroking/order/v1/getLtpData"
        headers = {"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"}
        body = [{"exchange": exchange, "symboltoken": str(token)}]
        r = requests.post(url, headers=headers, json=body, timeout=8)
        
        # Enhanced response parsing
        if r.status_code == 200:
            try:
                response_data = r.json()
                logger.debug("order-service response: %s", json.dumps(response_data, indent=2)[:500])
                return r.status_code, response_data
            except Exception:
                logger.debug("order-service response (non-JSON): %s", r.text[:400])
                return r.status_code, r.text
        else:
            logger.debug("order-service error %d: %s", r.status_code, r.text[:400])
            return r.status_code, r.text
            
    except Exception as e:
        logger.debug("order-service exception: %s", e)
        return None, f"EXC: {e}"

def rest_ltp_marketdata(token, exchange, jwt_token):
    """GET /rest/marketdata/ltp/v1 with enhanced parsing"""
    try:
        path = f"/rest/marketdata/ltp/v1?exchange={exchange}&symboltoken={token}" if exchange else f"/rest/marketdata/ltp/v1?symboltoken={token}"
        url = BASE_API_HOST.rstrip("/") + path
        headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
        r = requests.get(url, headers=headers, timeout=8)
        
        if r.status_code == 200:
            try:
                response_data = r.json()
                logger.debug("marketdata response: %s", json.dumps(response_data, indent=2)[:500])
                return r.status_code, response_data
            except Exception:
                logger.debug("marketdata response (non-JSON): %s", r.text[:400])
                return r.status_code, r.text
        else:
            logger.debug("marketdata error %d: %s", r.status_code, r.text[:400])
            return r.status_code, r.text
            
    except Exception as e:
        logger.debug("marketdata exception: %s", e)
        return None, f"EXC: {e}"

def rest_ltp_alternative(token, exchange, jwt_token):
    """Try alternative endpoint: /rest/secure/angelbroking/user/v1/getLtp"""
    try:
        url = BASE_API_HOST.rstrip("/") + "/rest/secure/angelbroking/user/v1/getLtp"
        headers = {"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"}
        body = {"exchange": exchange, "symboltoken": str(token)}
        r = requests.post(url, headers=headers, json=body, timeout=8)
        
        if r.status_code == 200:
            try:
                response_data = r.json()
                logger.debug("alternative LTP response: %s", json.dumps(response_data, indent=2)[:500])
                return r.status_code, response_data
            except Exception:
                return r.status_code, r.text
        else:
            logger.debug("alternative LTP error %d: %s", r.status_code, r.text[:400])
            return r.status_code, r.text
            
    except Exception as e:
        return None, f"EXC: {e}"

def get_ltp_multi_token(instrument_info, jwt_token=None):
    """
    Try multiple tokens for an instrument until one works
    """
    name = instrument_info.get("name", "UNKNOWN")
    tokens = instrument_info.get("tokens", [])
    exchange = instrument_info.get("exchange", "NSE")
    
    if not tokens:
        logger.warning("%s: No tokens to try", name)
        return None, "No tokens available"
    
    for i, token in enumerate(tokens):
        logger.info("%s: Trying token %s (%d/%d)", name, token, i+1, len(tokens))
        
        # Try SDK first
        try:
            info = {"exchange": exchange, "symboltoken": str(token)}
            if hasattr(s, "getLtp"):
                sdk_resp = s.getLtp(info)
                if sdk_resp and isinstance(sdk_resp, dict):
                    ltp = extract_ltp_from_response(sdk_resp)
                    if ltp is not None:
                        logger.info("%s: SDK success with token %s, LTP=%s", name, token, ltp)
                        return ltp, f"SDK:token_{token}"
        except Exception as e:
            logger.debug("%s: SDK failed for token %s: %s", name, token, e)
        
        # Try REST endpoints if JWT available
        if jwt_token:
            # Method 1: order-service
            try:
                st, resp = rest_ltp_order_service(token, exchange, jwt_token)
                if st == 200 and isinstance(resp, dict):
                    ltp = extract_ltp_from_response(resp)
                    if ltp is not None:
                        logger.info("%s: order-service success with token %s, LTP=%s", name, token, ltp)
                        return ltp, f"order-service:token_{token}"
            except Exception as e:
                logger.debug("%s: order-service failed for token %s: %s", name, token, e)
            
            # Method 2: marketdata
            try:
                st, resp = rest_ltp_marketdata(token, exchange, jwt_token)
                if st == 200 and isinstance(resp, dict):
                    ltp = extract_ltp_from_response(resp)
                    if ltp is not None:
                        logger.info("%s: marketdata success with token %s, LTP=%s", name, token, ltp)
                        return ltp, f"marketdata:token_{token}"
            except Exception as e:
                logger.debug("%s: marketdata failed for token %s: %s", name, token, e)
            
            # Method 3: alternative endpoint
            try:
                st, resp = rest_ltp_alternative(token, exchange, jwt_token)
                if st == 200 and isinstance(resp, dict):
                    ltp = extract_ltp_from_response(resp)
                    if ltp is not None:
                        logger.info("%s: alternative success with token %s, LTP=%s", name, token, ltp)
                        return ltp, f"alternative:token_{token}"
            except Exception as e:
                logger.debug("%s: alternative failed for token %s: %s", name, token, e)
    
    logger.warning("%s: All tokens exhausted, no LTP retrieved", name)
    return None, f"All {len(tokens)} tokens failed"

def extract_ltp_from_response(resp):
    """Enhanced LTP extraction for Angel One API quirks"""
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
            # Angel One specific patterns
            # Pattern 1: {"status":true,"message":"SUCCESS","errorcode":"","data":{"exchange":"NSE","tradingsymbol":"RELIANCE","symboltoken":"2885","open":2847.00,"high":2850.00,"low":2840.00,"close":2845.00,"ltp":2847.25}}
            data = resp.get("data")
            if isinstance(data, dict):
                # Direct LTP field
                if "ltp" in data:
                    try:
                        return float(data["ltp"])
                    except Exception:
                        pass
                
                # Common LTP field names
                for field in ["lastPrice", "lp", "LTP", "last_price", "close"]:
                    if field in data:
                        try:
                            return float(data[field])
                        except Exception:
                            pass
            
            # Pattern 2: {"status":true,"data":[{"exchange":"NSE","tradingsymbol":"RELIANCE","ltp":2847.25}]}
            if isinstance(data, list) and len(data) > 0:
                first_item = data[0]
                if isinstance(first_item, dict):
                    for field in ["ltp", "lastPrice", "lp", "LTP", "last_price", "close"]:
                        if field in first_item:
                            try:
                                return float(first_item[field])
                            except Exception:
                                pass
            
            # Pattern 3: Top-level LTP fields
            for field in ["ltp", "lastPrice", "lp", "LTP", "last_price", "close"]:
                if field in resp:
                    try:
                        return float(resp[field])
                    except Exception:
                        pass
            
            # Pattern 4: Nested in result
            result = resp.get("result")
            if isinstance(result, dict):
                for field in ["ltp", "lastPrice", "lp", "LTP", "last_price", "close"]:
                    if field in result:
                        try:
                            return float(result[field])
                        except Exception:
                            pass
        
        return None
    except Exception:
        logger.exception("extract_ltp_from_response failed for resp: %s", str(resp)[:200])
        return None

def resolve_instruments_from_master():
    """Enhanced instrument resolution with multiple symbol matching"""
    try:
        logger.info("Downloading instruments master: %s", INSTRUMENTS_URL)
        r = requests.get(INSTRUMENTS_URL, timeout=20)
        r.raise_for_status()
        data = r.json()
    except Exception:
        logger.exception("Failed to download instruments master")
        return {}

    rows = data if isinstance(data, list) else data.get("data", []) if isinstance(data, dict) else []
    
    # Enhanced matching for each instrument
    for inst_key, inst_config in INSTRUMENTS.items():
        symbols_to_match = inst_config.get("trading_symbols", [inst_config.get("symbol", "")])
        exchange = inst_config.get("exchange", "NSE")
        
        logger.info("Looking for %s symbols: %s in exchange: %s", inst_key, symbols_to_match, exchange)
        
        found_tokens = []
        for row in rows:
            try:
                trad_sym = (row.get("symbol") or row.get("tradingsymbol") or "").strip()
                exch = (row.get("exchange") or row.get("exch") or "").strip()
                token = row.get("token") or row.get("instrument_token") or row.get("symboltoken")
                
                if not trad_sym or not token:
                    continue
                
                # Check if this row matches our instrument
                if exch.upper() == exchange.upper():
                    for symbol_variant in symbols_to_match:
                        if trad_sym.upper() == symbol_variant.upper():
                            token_str = str(token)
                            if token_str not in found_tokens:
                                found_tokens.append(token_str)
                                logger.info("Found %s token: %s for symbol: %s", inst_key, token_str, trad_sym)
                            break
            except Exception:
                continue
        
        # Merge found tokens with existing ones (keep existing as primary)
        existing_tokens = inst_config.get("tokens", [])
        all_tokens = existing_tokens[:]  # Start with existing
        
        # Add newly found tokens that aren't already present
        for token in found_tokens:
            if token not in all_tokens:
                all_tokens.append(token)
        
        INSTRUMENTS[inst_key]["tokens"] = all_tokens
        logger.info("Final tokens for %s: %s", inst_key, all_tokens)

    return INSTRUMENTS

def poll_ltp_loop(jwt_token):
    if not jwt_token:
        logger.error("No JWT token; aborting poll loop")
        return

    # startup msg
    try:
        monitoring_list = ", ".join(list(INSTRUMENTS.keys()))
        telegram_send_text(f"🚀 Enhanced Bot online — Major Stocks LTP alerts\nMonitoring: {monitoring_list}\nPoll interval: {POLL_INTERVAL}s\n\n⚠️ NOTE: Using major stocks instead of indices\n(Angel One index data is currently broken)\n\nEnhancements:\n✅ Multiple token fallbacks\n✅ Enhanced response parsing\n✅ Better error diagnostics")
    except Exception:
        pass

    prev_ltps = {k: None for k in INSTRUMENTS.keys()}
    successful_methods = {}  # Track which method works for each instrument
    
    while True:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        logger.info("🔄 Polling LTP at %s", ts)
        
        for name, info in INSTRUMENTS.items():
            try:
                # Add name to info for logging
                info_with_name = dict(info)
                info_with_name["name"] = name
                
                ltp, method = get_ltp_multi_token(info_with_name, jwt_token)
                prev = prev_ltps.get(name)
                
                if ltp is None:
                    telegram_send_text(f"❌ <b>{name}</b>\nSignal: NO_DATA\nStatus: {method}\nTime: {ts}")
                    logger.warning("%s: LTP retrieval failed - %s", name, method)
                else:
                    # Track successful method
                    successful_methods[name] = method
                    
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
                    
                    # Format message
                    lines = [f"✅ <b>{name}</b>", f"Time: {ts}", f"LTP: ₹{ltp:.2f}"]
                    
                    if delta is not None:
                        emoji = "📈" if delta > 0 else "📉" if delta < 0 else "➡️"
                        sign = "+" if delta > 0 else ""
                        lines.append(f"Δ: {sign}{delta:.2f} ({sign}{pct:.2f}%) {emoji}")
                    else:
                        lines.append("Δ: (first reading)")
                    
                    lines.append(f"Method: {method}")
                    
                    telegram_send_text("\n".join(lines))
                    logger.info("✅ %s: LTP=%s via %s", name, ltp, method)
                
                time.sleep(0.5)  # Brief pause between instruments
                
            except Exception:
                logger.exception("❌ Error during LTP poll for %s", name)
                telegram_send_text(f"❌ <b>{name}</b>\nSignal: ERROR\nException occurred during data fetch\nTime: {ts}")
        
        # Summary log
        working_count = len([k for k, v in prev_ltps.items() if v is not None])
        logger.info("🔄 Cycle complete: %d/%d instruments successful. Sleeping %ds", 
                   working_count, len(INSTRUMENTS), POLL_INTERVAL)
        
        time.sleep(POLL_INTERVAL)

# ---------------- main ----------------
if __name__ == "__main__":
    logger.info("🚀 Starting Enhanced Angel One LTP Bot")
    
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("⚠️  Telegram vars missing; alerts will not be sent")

    # 1) Enhanced instrument resolution
    try:
        logger.info("🔍 Resolving instrument tokens...")
        resolve_instruments_from_master()
        
        # Send summary to Telegram
        token_summary = []
        for name, info in INSTRUMENTS.items():
            tokens = info.get("tokens", [])
            token_summary.append(f"{name}: {len(tokens)} tokens {tokens[:3]}{'...' if len(tokens) > 3 else ''}")
        
        telegram_send_text("🔍 Instrument Resolution Complete:\n" + "\n".join(token_summary))
        
    except Exception:
        logger.exception("❌ resolve_instruments_from_master failed")

    # 2) Login
    logger.info("🔐 Attempting login...")
    resp, jwt_token = login()
    if not resp or not jwt_token:
        error_msg = "❌ Login failed! Check credentials and TOTP"
        logger.error(error_msg)
        telegram_send_text(error_msg)
        sys.exit(1)
    
    telegram_send_text("✅ Login successful! Starting LTP monitoring...")

    # 3) Start enhanced poll loop
    try:
        poll_ltp_loop(jwt_token)
    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user")
        telegram_send_text("🛑 Bot stopped manually")
    except Exception:
        logger.exception("❌ Fatal error in poll loop")
        telegram_send_text("💥 Bot crashed! Check logs")
        raise
