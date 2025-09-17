#!/usr/bin/env python3
"""
SmartAPI market scanner:
- Auto fetch instruments
- MPIN+TOTP login
- Poll specified indices every N seconds (default 300)
- For each: fetch LTP and last 50 candles, render chart PNG, send Telegram alert (image + text)
"""

import os
import sys
import time
import datetime
import logging
import importlib
import traceback
import requests
import math

from dotenv import load_dotenv

# plotting
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

# config logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(asctime)s %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()

# ---------- ENV ----------
SMARTAPI_API_KEY = os.getenv("SMARTAPI_API_KEY", "").strip()
SMARTAPI_CLIENT_CODE = os.getenv("SMARTAPI_CLIENT_CODE", "").strip()
SMARTAPI_MPIN = os.getenv("SMARTAPI_MPIN", "").strip()
SMARTAPI_PASSWORD = os.getenv("SMARTAPI_PASSWORD", "").strip()
SMARTAPI_TOTP_SECRET = os.getenv("SMARTAPI_TOTP_SECRET", "").strip()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

POLL_INTERVAL = int(os.getenv("MARKET_POLL_INTERVAL_SECONDS", "300"))  # default 5 minutes

# Base host for REST fallback (may change based on your account)
BASE_API_HOST = os.getenv("SMARTAPI_BASE_URL", "https://apiconnect.angelone.in")

# default instruments (token None => auto-resolve)
INSTRUMENTS = {
    "NIFTY50": {"exchange": "NSE", "symbol": "NIFTY 50", "token": None},
    "BANKNIFTY": {"exchange": "NSE", "symbol": "BANKNIFTY", "token": None},
    "SENSEX": {"exchange": "BSE", "symbol": "SENSEX", "token": None},
}

# ---------- import SmartConnect flexibly ----------
SmartConnect = None
for name in ("smartapi", "SmartApi", "smartapi_python"):
    try:
        mod = importlib.import_module(name)
        if hasattr(mod, "SmartConnect"):
            SmartConnect = getattr(mod, "SmartConnect")
            logger.info("Using SmartConnect from %s", name)
            break
        if hasattr(mod, "smartConnect") and hasattr(mod.smartConnect, "SmartConnect"):
            SmartConnect = getattr(mod.smartConnect, "SmartConnect")
            logger.info("Using SmartConnect from %s.smartConnect", name)
            break
    except Exception:
        continue

if SmartConnect is None:
    logger.error("SmartConnect not found. Ensure smartapi-python is installed.")
    sys.exit(1)

# optional pyotp
try:
    import pyotp
except Exception:
    pyotp = None

# ---------- create SmartConnect ----------
try:
    try:
        s = SmartConnect(api_key=SMARTAPI_API_KEY)
    except TypeError:
        s = SmartConnect(SMARTAPI_API_KEY)
except Exception:
    logger.exception("SmartConnect init failed")
    sys.exit(1)

# ---------- login helpers ----------
def totp_now(secret):
    if not pyotp or not secret:
        return None
    try:
        return pyotp.TOTP(secret).now()
    except Exception:
        logger.exception("TOTP gen failed")
        return None

def login():
    """Return (resp_dict, jwt_token)"""
    if SMARTAPI_MPIN and SMARTAPI_TOTP_SECRET:
        code = totp_now(SMARTAPI_TOTP_SECRET)
        try:
            logger.info("Attempting MPIN+TOTP login")
            resp = s.generateSession(SMARTAPI_CLIENT_CODE, SMARTAPI_MPIN, code)
            jwt = None
            if isinstance(resp, dict):
                data = resp.get("data") or {}
                jwt = data.get("jwtToken")
                if jwt and jwt.startswith("Bearer "):
                    jwt = jwt.split(" ", 1)[1]
            return resp, jwt
        except Exception as e:
            logger.warning("MPIN login exception: %s", e)
            logger.debug(traceback.format_exc())
    # fallback
    if SMARTAPI_PASSWORD and SMARTAPI_TOTP_SECRET:
        code = totp_now(SMARTAPI_TOTP_SECRET)
        try:
            logger.info("Attempting password+TOTP login")
            resp = s.generateSession(SMARTAPI_CLIENT_CODE, SMARTAPI_PASSWORD, code)
            jwt = None
            if isinstance(resp, dict):
                data = resp.get("data") or {}
                jwt = data.get("jwtToken")
                if jwt and jwt.startswith("Bearer "):
                    jwt = jwt.split(" ", 1)[1]
            return resp, jwt
        except Exception as e:
            logger.warning("Password login exception: %s", e)
            logger.debug(traceback.format_exc())
    logger.error("No credentials (MPIN/password) available for login")
    return None, None

# ---------- auto instruments ----------
def fetch_instruments_sdk():
    """Try to fetch instruments via SDK (best-effort)."""
    try:
        # common method names
        if hasattr(s, "get_instruments"):
            return s.get_instruments()
        if hasattr(s, "getInstruments"):
            return s.getInstruments()
        if hasattr(s, "get_instrument") or hasattr(s, "getInstrument"):
            # not list-returning; skip
            return None
    except Exception:
        logger.debug("SDK instruments fetch failed", exc_info=True)
    return None

def resolve_instrument_tokens():
    """
    Try to find tokens for the index symbols in INSTRUMENTS.
    This per-SDK data shape varies; we attempt common heuristics.
    """
    data = fetch_instruments_sdk()
    if not data:
        logger.info("No instruments fetched via SDK; please populate INSTRUMENTS tokens manually if needed.")
        return

    # data might be list of dicts - try to match by symbol name
    try:
        if isinstance(data, dict):
            # maybe keyed by symbol
            items = []
            for k,v in data.items():
                if isinstance(v, dict):
                    v["_key"] = k
                    items.append(v)
        elif isinstance(data, (list, tuple)):
            items = list(data)
        else:
            items = []
    except Exception:
        items = []

    logger.info("Attempting to resolve tokens from fetched instruments (items=%d)", len(items))
    for name, meta in INSTRUMENTS.items():
        if meta.get("token"):
            continue
        want_sym = (meta.get("symbol") or "").lower()
        want_ex = (meta.get("exchange") or "").lower()
        found = None
        for it in items:
            # common fields: 'symbol', 'name', 'exchange', 'token', 'instrument_token'
            sym = str(it.get("symbol") or it.get("tradingsymbol") or it.get("name") or "").lower()
            ex = str(it.get("exchange") or it.get("exch") or it.get("ex") or "").lower()
            token = it.get("token") or it.get("instrument_token") or it.get("symboltoken") or it.get("tokenId")
            if not token:
                # also some SDKs put token as string under 'symbol-token' etc - attempt
                for k in it.keys():
                    if "token" in str(k).lower():
                        token = it.get(k)
                        break
            if not token:
                continue
            if want_sym and want_sym in sym:
                # if exchange matches or exchange absent, accept
                if not want_ex or (want_ex and want_ex in ex):
                    found = token
                    break
        if found:
            INSTRUMENTS[name]["token"] = found
            logger.info("Resolved %s -> token %s", name, found)
        else:
            logger.info("Could not resolve token for %s automatically", name)

# ---------- market data helpers ----------
def get_ltp(info, jwt_token=None):
    """Try SDK LTP then REST fallback"""
    try:
        # try SDK names
        if hasattr(s, "getLtp"):
            return s.getLtp(info if info is not None else "")
        if hasattr(s, "get_ltp"):
            return s.get_ltp(info)
        if hasattr(s, "getLtpData"):
            return s.getLtpData([info])
    except Exception:
        logger.debug("SDK LTP failed", exc_info=True)

    # REST fallback - require jwt_token and correct path
    if not jwt_token:
        logger.debug("No JWT for REST LTP fallback")
        return None
    try:
        if isinstance(info, dict):
            exch = info.get("exchange")
            token = info.get("token")
            path = f"/rest/marketdata/ltp/v1?exchange={exch}&symboltoken={token}"
        else:
            path = f"/rest/marketdata/ltp/v1?symboltoken={info}"
        url = BASE_API_HOST.rstrip("/") + path
        headers = {"Authorization": f"Bearer {jwt_token}"}
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        logger.exception("REST LTP failed")
        return None

def get_candles(info, jwt_token=None, interval="5minute", from_ts=None, to_ts=None):
    """Try SDK candle methods then REST fallback"""
    try:
        if hasattr(s, "getCandleData"):
            return s.getCandleData(info, interval, from_ts, to_ts)
        if hasattr(s, "get_candle_data"):
            return s.get_candle_data(info, interval, from_ts, to_ts)
        if hasattr(s, "getHistoricalData"):
            return s.getHistoricalData(info, interval, from_ts, to_ts)
    except Exception:
        logger.debug("SDK candle failed", exc_info=True)

    if not jwt_token:
        logger.debug("No JWT for REST candles fallback")
        return None
    try:
        params = {"symboltoken": info.get("token") if isinstance(info, dict) else info, "interval": interval}
        url = BASE_API_HOST.rstrip("/") + "/rest/marketdata/candle/v1"
        headers = {"Authorization": f"Bearer {jwt_token}"}
        r = requests.get(url, headers=headers, params=params, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception:
        logger.exception("REST candles failed")
        return None

# ---------- plotting ----------
def plot_candles_ohlc(ohlc_list, title, filepath):
    """
    ohlc_list: list of dicts with keys: timestamp (ms), open, high, low, close
    Saves PNG to filepath.
    Simple candlestick rendering using matplotlib rectangles and lines.
    """
    if not ohlc_list:
        logger.warning("No candles to plot for %s", title)
        return False
    try:
        times = [d["timestamp"] for d in ohlc_list]
        opens = [float(d["open"]) for d in ohlc_list]
        highs = [float(d["high"]) for d in ohlc_list]
        lows = [float(d["low"]) for d in ohlc_list]
        closes = [float(d["close"]) for d in ohlc_list]

        # convert timestamps ms -> matplotlib x as simple increasing ints for spacing
        x = list(range(len(times)))
        width = 0.6

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.set_title(title)
        ax.set_xlabel("Candle")
        ax.set_ylabel("Price")

        for xi, o, h, l, c in zip(x, opens, highs, lows, closes):
            # wick
            ax.plot([xi, xi], [l, h], linewidth=1)
            # body
            lower = min(o, c)
            height = abs(c - o)
            rect = Rectangle((xi - width/2, lower), width, height if height > 0 else 0.0001,
                             edgecolor='black', facecolor='white' if c >= o else 'black')
            ax.add_patch(rect)

        # nice limits and grid
        ax.set_xlim(-1, len(x))
        pad = (max(highs) - min(lows)) * 0.05
        ax.set_ylim(min(lows) - pad, max(highs) + pad)
        ax.grid(True, linestyle='--', linewidth=0.5)
        fig.tight_layout()
        fig.savefig(filepath)
        plt.close(fig)
        return True
    except Exception:
        logger.exception("Failed to plot candles")
        return False

# ---------- Telegram ----------
def telegram_send_text(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram credentials missing; cannot send text.")
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()
        return True
    except Exception:
        logger.exception("Telegram text send failed")
        return False

def telegram_send_photo(photo_path, caption=None):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram credentials missing; cannot send photo.")
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendPhoto"
        with open(photo_path, "rb") as f:
            files = {"photo": f}
            data = {"chat_id": TELEGRAM_CHAT_ID}
            if caption:
                data["caption"] = caption
                data["parse_mode"] = "HTML"
            r = requests.post(url, data=data, files=files, timeout=20)
            r.raise_for_status()
        return True
    except Exception:
        logger.exception("Telegram photo send failed")
        return False

# ---------- simple signal rule ----------
def simple_alert_rule(name, ltp, candles):
    """
    Basic heuristic:
    - If last close is > previous close by >0.5% -> 'BULLISH'
    - If last close < previous close by >0.5% -> 'BEARISH'
    - Else 'NEUTRAL'
    You can replace with more advanced strategies.
    """
    try:
        if not candles or len(candles) < 2:
            return "NO_DATA", ""
        last = float(candles[-1]["close"])
        prev = float(candles[-2]["close"])
        change_pct = (last - prev) / prev * 100.0 if prev != 0 else 0.0
        sig = "NEUTRAL"
        if change_pct > 0.5:
            sig = "BULLISH"
        elif change_pct < -0.5:
            sig = "BEARISH"
        text = f"{name} LTP={ltp} | Last close={last} | Change vs prev={change_pct:.2f}%"
        return sig, text
    except Exception:
        logger.exception("Alert rule failed")
        return "ERROR", ""

# ---------- main polling loop ----------
def fetch_and_alert_loop():
    # login to get JWT
    resp, jwt = login()
    if not resp or not jwt:
        logger.error("Login failed; aborting market loop")
        return

    # attempt auto-resolve tokens if missing
    tokens_missing = any(v.get("token") is None for v in INSTRUMENTS.values())
    if tokens_missing:
        logger.info("Attempting to auto-resolve instrument tokens via SDK")
        resolve_instrument_tokens()

    logger.info("Starting market polling every %s seconds", POLL_INTERVAL)
    while True:
        ts = datetime.datetime.utcnow().isoformat()
        logger.info("Polling at %s", ts)
        for name, info in INSTRUMENTS.items():
            try:
                token_info = info
                ltp_res = get_ltp(token_info, jwt)
                # SDK responses vary; attempt to extract numerical LTP
                ltp = None
                if isinstance(ltp_res, dict):
                    # common shapes
                    ltp = ltp_res.get("data") or ltp_res.get("ltp") or ltp_res.get("lastPrice") or ltp_res.get("LTP")
                    # sometimes nested
                    if isinstance(ltp, dict):
                        ltp = ltp.get("lp") or ltp.get("lastPrice")
                elif isinstance(ltp_res, (int, float, str)):
                    ltp = ltp_res
                else:
                    # fallback: try extracting numeric inside
                    ltp = str(ltp_res)[:200]
                candles_res = get_candles(token_info, jwt, interval="5minute")
                # normalize candles to list of dicts with timestamp/open/high/low/close
                candles = []
                if isinstance(candles_res, dict):
                    # SDK-specific shapes exist; try to detect common fields
                    # e.g. {"data":[[timestamp,open,high,low,close,...],...]}
                    data = candles_res.get("data") or candles_res.get("candles") or candles_res.get("result")
                    if isinstance(data, list) and data and isinstance(data[0], list):
                        # each inner list often: [timestamp,open,high,low,close,volume]
                        for row in data[-50:]:
                            candles.append({
                                "timestamp": int(row[0]),
                                "open": float(row[1]),
                                "high": float(row[2]),
                                "low": float(row[3]),
                                "close": float(row[4])
                            })
                    elif isinstance(data, list) and data and isinstance(data[0], dict):
                        # sometimes a list of dicts
                        for row in data[-50:]:
                            candles.append({
                                "timestamp": int(row.get("timestamp") or row.get("time") or 0),
                                "open": float(row.get("open") or row.get("o") or 0),
                                "high": float(row.get("high") or row.get("h") or 0),
                                "low": float(row.get("low") or row.get("l") or 0),
                                "close": float(row.get("close") or row.get("c") or 0)
                            })
                elif isinstance(candles_res, list):
                    for row in candles_res[-50:]:
                        if isinstance(row, (list, tuple)):
                            candles.append({
                                "timestamp": int(row[0]),
                                "open": float(row[1]),
                                "high": float(row[2]),
                                "low": float(row[3]),
                                "close": float(row[4])
                            })
                        elif isinstance(row, dict):
                            candles.append({
                                "timestamp": int(row.get("timestamp") or row.get("time") or 0),
                                "open": float(row.get("open") or row.get("o") or 0),
                                "high": float(row.get("high") or row.get("h") or 0),
                                "low": float(row.get("low") or row.get("l") or 0),
                                "close": float(row.get("close") or row.get("c") or 0)
                            })
                # if candles empty, skip plotting but still send LTP text
                chart_path = f"/tmp/{name.replace(' ','_')}_chart.png"
                plotted = False
                if candles:
                    # keep only last 50
                    if len(candles) > 50:
                        candles = candles[-50:]
                    plotted = plot_candles_ohlc(candles, f"{name} - last {len(candles)} candles", chart_path)
                # simple alert
                sig, text = simple_alert_rule(name, ltp, candles)
                caption = f"<b>{name}</b>\nSignal: {sig}\n{ text }"
                # send text then photo if present
                telegram_send_text(caption)
                if plotted:
                    telegram_send_photo(chart_path, caption=f"{name} chart")
                logger.info("Alert sent for %s (sig=%s)", name, sig)
            except Exception:
                logger.exception("Failed processing %s", name)
        logger.info("Polling cycle done; sleeping %s seconds", POLL_INTERVAL)
        time.sleep(POLL_INTERVAL)

# ---------- entry ----------
if __name__ == "__main__":
    # quick pre-checks
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram variables missing - alerts will not be sent (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)")
    # login once to validate creds
    r, token = login()
    if not r or not token:
        logger.error("Login failed during startup. Check credentials.")
        sys.exit(1)
    # resolve instrument tokens if possible
    resolve_instrument_tokens()
    # start loop
    fetch_and_alert_loop()
