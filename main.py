#!/usr/bin/env python3
"""
main.py - SmartAPI starter with market-data fetch (LTP + candlesticks)

Usage:
 - Fill .env with SMARTAPI_* creds (MPIN/TOTP/CLIENT_CODE/API_KEY).
 - Update INSTRUMENTS with correct exchange/token/symbol for NIFTY/SENSEX/BANKNIFTY.
 - Deploy and check logs.

Notes:
 - This script tries to use SmartConnect SDK methods if present (getLtp/getCandleData).
 - If SDK methods are not available, it falls back to simple REST calls using the JWT token.
 - Do NOT log sensitive tokens in production.
"""
import os
import sys
import time
import datetime
import logging
import importlib
import traceback

from dotenv import load_dotenv

# config logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(asctime)s %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()

# Environment / config
SMARTAPI_API_KEY = os.getenv("SMARTAPI_API_KEY", "").strip()
SMARTAPI_CLIENT_CODE = os.getenv("SMARTAPI_CLIENT_CODE", "").strip()
SMARTAPI_MPIN = os.getenv("SMARTAPI_MPIN", "").strip()
SMARTAPI_PASSWORD = os.getenv("SMARTAPI_PASSWORD", "").strip()
SMARTAPI_TOTP_SECRET = os.getenv("SMARTAPI_TOTP_SECRET", "").strip()
POLL_INTERVAL = int(os.getenv("MARKET_POLL_INTERVAL_SECONDS", "15"))

# Instruments mapping: you MUST replace tokens/identifiers with actual ones for your broker
# Example structure (fill with correct values):
# For SmartAPI you often need exchange + token (exchange may be 'NSE' / 'NFO' etc and token is instrument token)
# Put correct instrument identifiers here after using fetch_instruments() or from your broker
INSTRUMENTS = {
    "NIFTY50": {"exchange": "NSE", "symbol": "NIFTY 50", "token": None},
    "BANKNIFTY": {"exchange": "NSE", "symbol": "BANKNIFTY", "token": None},
    "SENSEX": {"exchange": "BSE", "symbol": "SENSEX", "token": None},
    # add more as needed...
}

# Helper to import SmartConnect flexibly
SmartConnect = None
for candidate in ("smartapi", "SmartApi", "smartapi_python"):
    try:
        mod = importlib.import_module(candidate)
        if hasattr(mod, "SmartConnect"):
            SmartConnect = getattr(mod, "SmartConnect")
            logger.info("Using SmartConnect from module '%s' -> %s", candidate, getattr(mod, "__file__", None))
            break
        # some packages expose class in submodule
        if hasattr(mod, "smartConnect") and hasattr(mod.smartConnect, "SmartConnect"):
            SmartConnect = getattr(mod.smartConnect, "SmartConnect")
            logger.info("Using SmartConnect from submodule '%s.smartConnect'", candidate)
            break
    except Exception:
        continue

if SmartConnect is None:
    logger.error("SmartConnect import failed. Ensure smartapi-python or compatible package is installed.")
    sys.exit(1)

# try import pyotp
try:
    import pyotp
except Exception:
    pyotp = None

# create SmartConnect instance
try:
    try:
        s = SmartConnect(api_key=SMARTAPI_API_KEY)
    except TypeError:
        s = SmartConnect(SMARTAPI_API_KEY)
except Exception:
    logger.exception("SmartConnect initialization failed.")
    sys.exit(1)

# ---------- Login helpers (MPIN+TOTP primary, fallback to password+TOTP) ----------
def totp_now(secret):
    if not pyotp or not secret:
        return None
    try:
        return pyotp.TOTP(secret).now()
    except Exception:
        logger.exception("TOTP generation failed")
        return None

def login():
    """
    Perform login and return (response_dict, jwt_token_str or None)
    response_dict: raw response from generateSession
    jwt_token_str: token without 'Bearer ' prefix
    """
    if not SMARTAPI_CLIENT_CODE:
        logger.error("SMARTAPI_CLIENT_CODE missing")
        return None, None

    # prefer MPIN + TOTP
    if SMARTAPI_MPIN and SMARTAPI_TOTP_SECRET:
        code = totp_now(SMARTAPI_TOTP_SECRET)
        try:
            logger.info("Attempting MPIN+TOTP login")
            resp = s.generateSession(SMARTAPI_CLIENT_CODE, SMARTAPI_MPIN, code)
            logger.info("Login response status=%s message=%s", resp.get("status"), resp.get("message"))
            jwt = None
            if resp and isinstance(resp, dict):
                data = resp.get("data") or {}
                jwt = data.get("jwtToken") or data.get("token") or None
                if jwt and jwt.startswith("Bearer "):
                    jwt = jwt.split(" ", 1)[1]
            return resp, jwt
        except Exception as e:
            logger.warning("MPIN login exception: %s", e)
            logger.debug(traceback.format_exc())

    # fallback password+TOTP if allowed
    if SMARTAPI_PASSWORD and SMARTAPI_TOTP_SECRET:
        code = totp_now(SMARTAPI_TOTP_SECRET)
        try:
            logger.info("Attempting Password+TOTP login (fallback)")
            resp = s.generateSession(SMARTAPI_CLIENT_CODE, SMARTAPI_PASSWORD, code)
            logger.info("Login response status=%s message=%s", resp.get("status"), resp.get("message"))
            jwt = None
            if resp and isinstance(resp, dict):
                data = resp.get("data") or {}
                jwt = data.get("jwtToken") or data.get("token") or None
                if jwt and jwt.startswith("Bearer "):
                    jwt = jwt.split(" ", 1)[1]
            return resp, jwt
        except Exception as e:
            logger.warning("Password login exception: %s", e)
            logger.debug(traceback.format_exc())

    logger.error("No suitable credentials available for login (MPIN/password/TOTP)")
    return None, None

# ---------- Instrument helpers ----------
def fetch_instruments(exchange=None):
    """
    Try to fetch instruments using SDK if available, otherwise advise user.
    Returns list/dict as provided by SDK.
    """
    try:
        # SDK often has get_instruments or get_instruments_by_exchange; try common names
        if hasattr(s, "get_instruments"):
            logger.info("Fetching instruments via s.get_instruments()")
            return s.get_instruments()
        if hasattr(s, "getInstruments"):
            logger.info("Fetching instruments via s.getInstruments()")
            return s.getInstruments()
        if hasattr(s, "get_instruments_by_exchange") and exchange:
            return s.get_instruments_by_exchange(exchange)
    except Exception:
        logger.exception("Failed to fetch instruments via SDK")
    logger.info("Instrument fetch not available via SDK - please populate INSTRUMENTS dict manually.")
    return None

# ---------- Market data fetchers ----------
def get_ltp_via_sdk(symbol_token):
    """
    Try SDK getLtp/get_ltp style calls. symbol_token can be simple token or instrument dict as required by SDK.
    """
    try:
        if hasattr(s, "getLtp"):
            return s.getLtp(symbol_token)
        if hasattr(s, "get_ltp"):
            return s.get_ltp(symbol_token)
        # some SDKs accept list of instruments
        if hasattr(s, "getLtpData"):
            return s.getLtpData([symbol_token])
    except Exception:
        logger.debug("SDK LTP call failed", exc_info=True)
    return None

def get_candles_via_sdk(symbol_token, interval="5minute", from_time=None, to_time=None):
    """
    Try SDK candle methods. interval naming depends on SDK ('1minute','5minute','day' etc).
    """
    try:
        if hasattr(s, "getCandleData"):
            return s.getCandleData(symbol_token, interval, from_time, to_time)
        if hasattr(s, "get_candle_data"):
            return s.get_candle_data(symbol_token, interval, from_time, to_time)
        if hasattr(s, "getHistoricalData"):
            return s.getHistoricalData(symbol_token, interval, from_time, to_time)
    except Exception:
        logger.debug("SDK candle call failed", exc_info=True)
    return None

# REST fallback using JWT (generic)
import requests

BASE_API_HOST = os.getenv("SMARTAPI_BASE_URL", "https://apiconnect.angelone.in")  # or apiconnect.angelbroking.com based on account
def rest_get(path, jwt_token, params=None):
    url = BASE_API_HOST.rstrip("/") + path
    headers = {"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"}
    r = requests.get(url, headers=headers, params=params, timeout=10)
    r.raise_for_status()
    try:
        return r.json()
    except Exception as e:
        logger.exception("Failed to parse JSON from %s", url)
        return None

def rest_post(path, jwt_token, payload=None):
    url = BASE_API_HOST.rstrip("/") + path
    headers = {"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"}
    r = requests.post(url, headers=headers, json=payload, timeout=10)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        logger.exception("Failed to parse JSON from %s", url)
        return None

def get_ltp(symbol_info, jwt_token=None):
    """
    symbol_info: either token string or dict with exchange/symbol/token
    """
    # 1) try SDK call
    sdk_res = None
    try:
        sdk_res = get_ltp_via_sdk(symbol_info if symbol_info is not None else "")
    except Exception:
        sdk_res = None
    if sdk_res:
        return sdk_res

    # 2) fallback REST: you need correct endpoint for your broker
    # Example REST path (may vary) - you must confirm with SmartAPI docs
    if jwt_token is None:
        logger.debug("No JWT token for REST LTP call")
        return None
    # Example: /marketdata/ltp?exchange=...&token=...
    if isinstance(symbol_info, dict):
        exch = symbol_info.get("exchange")
        token = symbol_info.get("token")
        path = f"/rest/marketdata/ltp/v1?exchange={exch}&symboltoken={token}"
    else:
        # if you have raw token
        path = f"/rest/marketdata/ltp/v1?symboltoken={symbol_info}"
    try:
        return rest_get(path, jwt_token)
    except Exception:
        logger.exception("REST LTP call failed")
        return None

def get_candles(symbol_info, jwt_token=None, interval="5minute", from_ts=None, to_ts=None):
    # 1) try SDK
    sdk_res = get_candles_via_sdk(symbol_info, interval, from_ts, to_ts)
    if sdk_res:
        return sdk_res

    if jwt_token is None:
        logger.debug("No JWT for REST candle call")
        return None

    # Example REST path for candlesticks - please confirm exact API path in docs
    # This is a placeholder pattern and may need update per your SmartAPI version.
    if isinstance(symbol_info, dict):
        exch = symbol_info.get("exchange")
        token = symbol_info.get("token")
        params = {"symboltoken": token, "interval": interval}
    else:
        params = {"symboltoken": symbol_info, "interval": interval}
    try:
        return rest_get("/rest/marketdata/candle/v1", jwt_token, params=params)
    except Exception:
        logger.exception("REST candle call failed")
        return None

# ---------- Orchestration: login then poll market data ----------
def fetch_loop():
    resp, jwt = login()
    if not resp or not jwt:
        logger.error("Login failed - cannot fetch market data")
        return

    logger.info("Authenticated - starting market data polling (interval=%ss)", POLL_INTERVAL)

    while True:
        now = datetime.datetime.utcnow().isoformat()
        logger.info("Polling market data at %s", now)
        for name, info in INSTRUMENTS.items():
            try:
                ltp = get_ltp(info, jwt)
                # SDK LTP formats differ; just print raw result for now
                logger.info("%s LTP: %s", name, ltp)
                # fetch candles (5min example)
                end_ts = int(time.time() * 1000)
                start_ts = end_ts - (60 * 60 * 1000)  # last 1 hour in ms
                candles = get_candles(info, jwt, interval="5minute", from_ts=start_ts, to_ts=end_ts)
                logger.info("%s candles: %s", name, candles if candles else "no-data")
            except Exception:
                logger.exception("Failed fetch for %s", name)
        time.sleep(POLL_INTERVAL)

# ---------- Entry point ----------
if __name__ == "__main__":
    # If INSTRUMENTS tokens not set, attempt to fetch instruments (helpful)
    tokens_missing = any(v.get("token") is None for v in INSTRUMENTS.values())
    if tokens_missing:
        logger.info("Some instrument tokens are missing; attempting to fetch instruments (SDK)...")
        instruments_data = fetch_instruments()
        if instruments_data:
            logger.info("Fetched instruments count: %s", len(instruments_data) if hasattr(instruments_data, "__len__") else "unknown")
            # Attempt to auto-fill if possible (best-effort)
            # NOTE: instruments_data structure varies by SDK; inspect and adapt as needed
        else:
            logger.info("Instrument auto-fetch not available; please fill INSTRUMENTS dict with correct token/ids.")
    fetch_loop()
