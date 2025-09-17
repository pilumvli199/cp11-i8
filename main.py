#!/usr/bin/env python3
"""
main.py - SmartAPI market scanner
- Single startup login (MPIN+TOTP preferred) -> reuse JWT in polling loop
- Auto-download instruments master JSON to resolve tokens for indices
- Poll indices every MARKET_POLL_INTERVAL_SECONDS (default 300s)
- For each: fetch LTP and last ~50 candles, render chart PNG, send Telegram text+image alert
- Simple alert rule (change vs prev candle)
"""

import os
import sys
import time
import datetime
import logging
import importlib
import traceback
import requests
import json

from dotenv import load_dotenv

# plotting (non-interactive)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

# Logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(asctime)s %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()

# ---------------- ENV VARS ----------------
SMARTAPI_API_KEY = os.getenv("SMARTAPI_API_KEY", "").strip()
SMARTAPI_CLIENT_CODE = os.getenv("SMARTAPI_CLIENT_CODE", "").strip()
SMARTAPI_MPIN = os.getenv("SMARTAPI_MPIN", "").strip()
SMARTAPI_PASSWORD = os.getenv("SMARTAPI_PASSWORD", "").strip()
SMARTAPI_TOTP_SECRET = os.getenv("SMARTAPI_TOTP_SECRET", "").strip()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

POLL_INTERVAL = int(os.getenv("MARKET_POLL_INTERVAL_SECONDS", "300"))  # default 300s = 5min
BASE_API_HOST = os.getenv("SMARTAPI_BASE_URL", "https://apiconnect.angelone.in")

# Instruments master URL (AngelOne docs)
INSTRUMENTS_URL = os.getenv("INSTRUMENTS_URL",
                            "https://margincalculator.angelone.in/OpenAPI_File/files/OpenAPIScripMaster.json")

# ---------------- DEFAULTS (will try to auto-resolve) ----------------
# Keep token=None to let auto-resolve fill it. Manual token overrides can be typed here.
INSTRUMENTS = {
    "NIFTY50":   {"exchange": "NSE", "symbol": "NIFTY 50",  "token": None},
    "BANKNIFTY": {"exchange": "NSE", "symbol": "BANKNIFTY",  "token": None},
    "SENSEX":    {"exchange": "BSE", "symbol": "SENSEX",     "token": None},
}

# ---------------- SmartConnect import ----------------
SmartConnect = None
for candidate in ("smartapi", "SmartApi", "smartapi_python"):
    try:
        mod = importlib.import_module(candidate)
        # try common exposures
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
    logger.error("SmartConnect import failed. Install 'smartapi-python' and ensure package present.")
    sys.exit(1)

# create SmartConnect instance
try:
    try:
        s = SmartConnect(api_key=SMARTAPI_API_KEY)
    except TypeError:
        s = SmartConnect(SMARTAPI_API_KEY)
except Exception:
    logger.exception("SmartConnect init failed")
    sys.exit(1)

# optional pyotp import
try:
    import pyotp
except Exception:
    pyotp = None

# ---------------- Utilities / Login ----------------
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
    """Attempt MPIN+TOTP first, then password+TOTP fallback. Return (resp, jwt)."""
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
    logger.error("No valid credentials for login found (MPIN/password/TOTP).")
    return None, None

# ---------------- Instruments master download & resolve ----------------
def resolve_instruments_from_master():
    """
    Download instrument master JSON (OpenAPIScripMaster.json) and map desired indices to tokens.
    Updates INSTRUMENTS in-place for NIFTY50, BANKNIFTY, SENSEX if found.
    """
    try:
        logger.info("Downloading instruments master from %s", INSTRUMENTS_URL)
        r = requests.get(INSTRUMENTS_URL, timeout=20)
        r.raise_for_status()
        data = r.json()
    except Exception:
        logger.exception("Failed to download or parse instruments master JSON")
        return None

    # expected 'data' is list of dicts; keys: 'symbol'/'tradingsymbol', 'exchange', 'token', etc.
    if not isinstance(data, (list, tuple)):
        # some endpoints wrap in { "data": [...] }
        if isinstance(data, dict) and isinstance(data.get("data"), (list, tuple)):
            rows = data.get("data")
        else:
            rows = []
    else:
        rows = data

    logger.info("Downloaded instruments master rows=%d", len(rows))

    # mapping of string to our keys; sometimes symbol values differ; check common variants
    wanted_map = {
        "NIFTY 50": "NIFTY50",
        "NIFTY50": "NIFTY50",
        "BANKNIFTY": "BANKNIFTY",
        "BANK NIFTY": "BANKNIFTY",
        "SENSEX": "SENSEX",
        "S&P BSE SENSEX": "SENSEX",
    }

    found = {}
    # iterate rows and try to find matches
    for row in rows:
        try:
            # many masters use 'symbol' or 'tradingsymbol'
            trad_sym = (row.get("symbol") or row.get("tradingsymbol") or "").strip()
            exch = (row.get("exchange") or row.get("exch") or "").strip()
            token = row.get("token") or row.get("instrument_token") or row.get("symboltoken") or row.get("tokenId")
            # some masters store token as string/number; normalize to str
            if token is None:
                # try other keys
                for k, v in row.items():
                    if "token" in str(k).lower():
                        token = v
                        break
            if token is None:
                continue
            # normalize trad_sym for matching
            key = None
            if trad_sym in wanted_map:
                key = wanted_map[trad_sym]
            else:
                # try case-insensitive contains
                for candidate, mapped in wanted_map.items():
                    if candidate.lower() in trad_sym.lower():
                        key = mapped
                        break
            if key:
                found[key] = {"exchange": exch, "symbol": trad_sym, "token": str(token)}
        except Exception:
            continue

    if found:
        # update INSTRUMENTS for keys present
        for k, v in found.items():
            INSTRUMENTS[k]["exchange"] = v.get("exchange", INSTRUMENTS.get(k, {}).get("exchange"))
            INSTRUMENTS[k]["symbol"] = v.get("symbol", INSTRUMENTS.get(k, {}).get("symbol"))
            INSTRUMENTS[k]["token"] = v.get("token")
        logger.info("Resolved instruments from master: %s", {k: INSTRUMENTS[k]["token"] for k in INSTRUMENTS})
    else:
        logger.warning("No desired instruments resolved from master; tokens remain as-is.")
    return found

# ---------------- Telegram helpers ----------------
def telegram_send_text(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram credentials missing; skipping send_text")
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

def telegram_send_photo(photo_path, caption=None):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram credentials missing; skipping send_photo")
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
        logger.exception("telegram_send_photo failed")
        return False

# ---------------- Market data helpers (SDK-first, REST fallback) ----------------
def get_ltp(info, jwt_token=None):
    """
    info: either dict with token/exchange or a token string
    """
    try:
        if hasattr(s, "getLtp"):
            return s.getLtp(info)
        if hasattr(s, "get_ltp"):
            return s.get_ltp(info)
        if hasattr(s, "getLtpData"):
            return s.getLtpData([info])
    except Exception:
        logger.debug("SDK get_ltp failed", exc_info=True)

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
    """
    Request historical candles. SDK method names vary; try multiple names, else REST fallback.
    """
    try:
        if hasattr(s, "getCandleData"):
            return s.getCandleData(info, interval, from_ts, to_ts)
        if hasattr(s, "get_historical_data"):
            return s.get_historical_data(info, interval, from_ts, to_ts)
        if hasattr(s, "getHistoricalData"):
            return s.getHistoricalData(info, interval, from_ts, to_ts)
    except Exception:
        logger.debug("SDK get_candles failed", exc_info=True)

    if not jwt_token:
        logger.debug("No JWT for REST candles fallback")
        return None
    try:
        params = {"symboltoken": info.get("token") if isinstance(info, dict) else info, "interval": interval}
        url = BASE_API_HOST.rstrip("/") + "/rest/marketdata/candle/v1"
        headers = {"Authorization": f"Bearer {jwt_token}"}
        r = requests.get(url, headers=headers, params=params, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception:
        logger.exception("REST candles failed")
        return None

# ---------------- plotting ----------------
def plot_candles_ohlc(ohlc_list, title, filepath):
    if not ohlc_list:
        logger.warning("No candles to plot for %s", title)
        return False
    try:
        opens = [float(d["open"]) for d in ohlc_list]
        highs = [float(d["high"]) for d in ohlc_list]
        lows = [float(d["low"]) for d in ohlc_list]
        closes = [float(d["close"]) for d in ohlc_list]
        x = list(range(len(ohlc_list)))
        width = 0.6
        fig, ax = plt.subplots(figsize=(10,5))
        ax.set_title(title)
        ax.set_xlabel("Candle")
        ax.set_ylabel("Price")
        for xi, o, h, l, c in zip(x, opens, highs, lows, closes):
            ax.plot([xi, xi], [l, h], linewidth=1, color='black')
            lower = min(o, c)
            height = abs(c - o)
            color = 'green' if c >= o else 'red'
            rect = Rectangle((xi - width/2, lower), width, height if height > 0 else 0.0001,
                             facecolor=color, edgecolor='black')
            ax.add_patch(rect)
        ax.set_xlim(-1, len(x))
        pad = (max(highs) - min(lows)) * 0.05
        ax.set_ylim(min(lows) - pad, max(highs) + pad)
        ax.grid(True, linestyle='--', linewidth=0.5)
        fig.tight_layout()
        fig.savefig(filepath)
        plt.close(fig)
        return True
    except Exception:
        logger.exception("plot_candles_ohlc failed")
        return False

# ---------------- simple alert rule ----------------
def simple_alert_rule(name, ltp, candles):
    try:
        if not candles or len(candles) < 2:
            return "NO_DATA", f"{name}: No candle data available"
        last = float(candles[-1]["close"])
        prev = float(candles[-2]["close"])
        change_pct = (last - prev) / prev * 100.0 if prev != 0 else 0.0
        sig = "NEUTRAL"
        if change_pct > 0.5:
            sig = "BULLISH"
        elif change_pct < -0.5:
            sig = "BEARISH"
        text = f"LTP={ltp} | LastClose={last} | ChangeVsPrev={change_pct:.2f}%"
        return sig, text
    except Exception:
        logger.exception("simple_alert_rule failed")
        return "ERROR", ""

# ---------------- polling loop ----------------
def fetch_and_alert_loop(jwt_token):
    """
    Polling loop that uses the provided jwt_token (no internal login).
    """
    if not jwt_token:
        logger.error("fetch_and_alert_loop requires a valid jwt_token")
        return

    # post startup message
    try:
        monitoring_list = ", ".join(list(INSTRUMENTS.keys()))
        telegram_send_text(f"📡 Bot online — Manual mode. Monitoring: {monitoring_list}")
    except Exception:
        pass

    logger.info("Starting polling every %s seconds", POLL_INTERVAL)
    while True:
        ts = datetime.datetime.utcnow().isoformat()
        logger.info("Polling at %s", ts)
        for name, info in INSTRUMENTS.items():
            try:
                # check token presence
                if not info.get("token"):
                    logger.warning("Skipping %s - token missing", name)
                    telegram_send_text(f"{name}\nSignal: NO_DATA\n{name}: token missing - could not fetch data")
                    continue

                ltp_res = get_ltp(info, jwt_token)
                # extract scalar LTP
                ltp_val = None
                if isinstance(ltp_res, dict):
                    ltp_val = ltp_res.get("data") or ltp_res.get("ltp") or ltp_res.get("lastPrice") or ltp_res.get("LTP")
                    if isinstance(ltp_val, dict):
                        ltp_val = ltp_val.get("lp") or ltp_val.get("lastPrice")
                elif isinstance(ltp_res, (int, float, str)):
                    ltp_val = ltp_res
                else:
                    ltp_val = str(ltp_res)[:200]

                candles_res = get_candles(info, jwt_token, interval="5minute")
                candles = []
                # normalize to list of dicts
                if isinstance(candles_res, dict):
                    data = candles_res.get("data") or candles_res.get("candles") or candles_res.get("result")
                    if isinstance(data, list) and data and isinstance(data[0], list):
                        for row in data[-50:]:
                            candles.append({"timestamp": int(row[0]), "open": float(row[1]), "high": float(row[2]), "low": float(row[3]), "close": float(row[4])})
                    elif isinstance(data, list) and data and isinstance(data[0], dict):
                        for row in data[-50:]:
                            candles.append({"timestamp": int(row.get("timestamp") or row.get("time") or 0), "open": float(row.get("open") or row.get("o") or 0), "high": float(row.get("high") or row.get("h") or 0), "low": float(row.get("low") or row.get("l") or 0), "close": float(row.get("close") or row.get("c") or 0)})
                elif isinstance(candles_res, list):
                    for row in candles_res[-50:]:
                        if isinstance(row, (list, tuple)):
                            candles.append({"timestamp": int(row[0]), "open": float(row[1]), "high": float(row[2]), "low": float(row[3]), "close": float(row[4])})
                        elif isinstance(row, dict):
                            candles.append({"timestamp": int(row.get("timestamp") or row.get("time") or 0), "open": float(row.get("open") or row.get("o") or 0), "high": float(row.get("high") or row.get("h") or 0), "low": float(row.get("low") or row.get("l") or 0), "close": float(row.get("close") or row.get("c") or 0)})
                # plotting
                chart_path = f"/tmp/{name.replace(' ', '_')}_chart.png"
                plotted = False
                if candles:
                    if len(candles) > 50:
                        candles = candles[-50:]
                    plotted = plot_candles_ohlc(candles, f"{name} - last {len(candles)} candles", chart_path)
                # generate alert
                sig, text = simple_alert_rule(name, ltp_val, candles)
                caption = f"<b>{name}</b>\nSignal: {sig}\n{text}"
                telegram_send_text(caption)
                if plotted:
                    telegram_send_photo(chart_path, caption=f"{name} chart")
                logger.info("Processed %s (sig=%s)", name, sig)
            except Exception:
                logger.exception("Error processing %s", name)
        logger.info("Polling cycle complete; sleeping %s seconds", POLL_INTERVAL)
        time.sleep(POLL_INTERVAL)

# ---------------- entrypoint ----------------
if __name__ == "__main__":
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram vars missing; alerts will not be sent (set TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_ID)")

    # 1) Attempt to auto-resolve instruments from remote master JSON
    try:
        resolved = resolve_instruments_from_master()
        if resolved:
            logger.info("Instruments resolved from master: %s", resolved)
            # optionally send summary to Telegram for debugging
            try:
                telegram_send_text(f"Instrument tokens auto-resolved: {json.dumps({k: INSTRUMENTS[k]['token'] for k in INSTRUMENTS}, indent=0)[:2000]}")
            except Exception:
                pass
        else:
            logger.info("No instruments resolved from master. If tokens missing you may need to set INSTRUMENTS tokens manually.")
    except Exception:
        logger.exception("resolve_instruments_from_master() raised an exception")

    # 2) Single startup login, reuse JWT in loop
    resp, jwt_token = login()
    if not resp or not jwt_token:
        logger.error("Startup login failed. Check credentials and TOTP. Exiting.")
        sys.exit(1)

    # 3) Start polling loop with obtained JWT
    fetch_and_alert_loop(jwt_token)
