import os
import time
import json
import logging
import requests
import pyotp
from dotenv import load_dotenv
from SmartApi.smartConnect import SmartConnect
import telegram

# Load .env
load_dotenv()

# Logger setup
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(asctime)s %(message)s")
logger = logging.getLogger(__name__)

# Telegram setup
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)

def send_telegram(msg: str):
    try:
        bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=msg)
    except Exception as e:
        logger.error("Telegram send failed: %s", e)

# SmartAPI credentials
SMARTAPI_CLIENT_CODE = os.getenv("SMARTAPI_CLIENT_CODE")
SMARTAPI_MPIN = os.getenv("SMARTAPI_MPIN")
SMARTAPI_PASSWORD = os.getenv("SMARTAPI_PASSWORD")
SMARTAPI_TOTP_SECRET = os.getenv("SMARTAPI_TOTP_SECRET")
SMARTAPI_API_KEY = os.getenv("SMARTAPI_API_KEY")

# AngelOne endpoints
INSTRUMENTS_URL = "https://margincalculator.angelone.in/OpenAPI_File/files/OpenAPIScripMaster.json"

# Watchlist
WATCHLIST = ["NIFTY50", "BANKNIFTY", "SENSEX", "RELIANCE", "HDFCBANK", "INFY", "TCS", "ITC"]

# Global instruments map
INSTRUMENTS = {}

def resolve_instruments():
    """Fetch instruments master & resolve tokens for watchlist symbols."""
    try:
        r = requests.get(INSTRUMENTS_URL, timeout=20)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.error("Instrument master download failed: %s", e)
        return

    resolved = {}
    for row in data:
        tradingsymbol = row.get("symbol") or row.get("tradingsymbol")
        if not tradingsymbol:
            continue
        if tradingsymbol in ["NIFTY", "NIFTY50"]:
            resolved["NIFTY50"] = {
                "exchange": row.get("exchange"),
                "token": row.get("token"),
                "symbol": tradingsymbol,
            }
        elif tradingsymbol == "BANKNIFTY":
            resolved["BANKNIFTY"] = {
                "exchange": row.get("exchange"),
                "token": row.get("token"),
                "symbol": tradingsymbol,
            }
        elif tradingsymbol == "SENSEX":
            resolved["SENSEX"] = {
                "exchange": row.get("exchange"),
                "token": row.get("token"),
                "symbol": tradingsymbol,
            }
        elif tradingsymbol in WATCHLIST:
            resolved[tradingsymbol] = {
                "exchange": row.get("exchange"),
                "token": row.get("token"),
                "symbol": tradingsymbol,
            }

    # Manual overrides from .env
    for sym in WATCHLIST:
        override = os.getenv(f"TOKEN_{sym}")
        if override:
            if sym not in resolved:
                resolved[sym] = {"exchange": "NSE", "symbol": sym}
            resolved[sym]["token"] = override
            logger.info("Manual override token set for %s -> %s", sym, override)

    INSTRUMENTS.update(resolved)

    # Telegram dump
    dump_lines = ["📡 Resolved instruments:"]
    for k, v in INSTRUMENTS.items():
        dump_lines.append(f"{k}: exch={v.get('exchange')} token={v.get('token')} sym={v.get('symbol')}")
    send_telegram("\n".join(dump_lines))


def generate_totp(secret):
    return pyotp.TOTP(secret).now()

def login_smartapi():
    logger.info("Using SmartConnect from SmartApi")
    s = SmartConnect(api_key=SMARTAPI_API_KEY)

    try:
        code = generate_totp(SMARTAPI_TOTP_SECRET)
        data = s.generateSession(SMARTAPI_CLIENT_CODE, SMARTAPI_PASSWORD, code)
        if data and data.get("status"):
            logger.info("Login status=True message=%s", data.get("message"))
            send_telegram("✅ Login successful! Starting Phase1 LTP monitoring...")
            return s
        else:
            logger.error("Login failed: %s", data)
            send_telegram("❌ Login failed. Check credentials.")
            return None
    except Exception as e:
        logger.exception("Login exception")
        send_telegram(f"❌ Login exception: {e}")
        return None

def fetch_ltp(s, symbol):
    """Fetch LTP for given symbol."""
    if symbol not in INSTRUMENTS:
        return None

    inst = INSTRUMENTS[symbol]
    try:
        data = s.ltpData(inst["exchange"], inst["symbol"], inst["token"])
        if data and data.get("data"):
            return data["data"].get("ltp")
    except Exception as e:
        logger.warning("LTP fetch failed for %s: %s", symbol, e)
    return None

def phase1_loop(s):
    """Every 60s fetch LTP for watchlist."""
    while True:
        lines = ["📡 Phase1 LTP Alerts"]
        for sym in WATCHLIST:
            ltp = fetch_ltp(s, sym)
            if ltp:
                lines.append(f"✅ {sym}: {ltp}")
            else:
                lines.append(f"❌ {sym}: NO_DATA")
        send_telegram("\n".join(lines))
        time.sleep(60)

if __name__ == "__main__":
    resolve_instruments()
    s = login_smartapi()
    if s:
        phase1_loop(s)
