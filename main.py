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
    global INSTRUMENTS  # Declare global to modify it
    INSTRUMENTS = {}  # Start fresh

    try:
        r = requests.get(INSTRUMENTS_URL, timeout=20)
        r.raise_for_status()
        data = r.json()
        logger.info("Fetched instrument master with %s records", len(data))
    except Exception as e:
        logger.error("Instrument master download failed: %s", e)
        send_telegram("❌ Instrument master download failed. Using manual tokens.")
        # Proceed with manual tokens only if download fails
        data = []

    resolved = {}
    # First, try to find our watchlist symbols in the downloaded data
    for row in data:
        name = row.get("name", "").upper()
        tradingsymbol = row.get("tradingsymbol", "").upper()
        symbol = row.get("symbol", "").upper()
        exch = row.get("exchange", "")

        # Check for matches in our WATCHLIST
        for watch_symbol in WATCHLIST:
            # Check if any of the fields contain our watchlist symbol
            if (watch_symbol in name or
                 watch_symbol == tradingsymbol or
                 watch_symbol == symbol):
                resolved[watch_symbol] = {
                    "exchange": exch,
                    "token": row.get("token"),
                    "symbol": tradingsymbol or symbol or name,
                }
                logger.info("Resolved %s -> token %s on %s", watch_symbol, resolved[watch_symbol]["token"], exch)
                break  # Move to next watch symbol once found

    # Manual overrides from .env - ALWAYS takes precedence
    for sym in WATCHLIST:
        override_token = os.getenv(f"TOKEN_{sym}")
        override_exch = os.getenv(f"EXCH_{sym}", "NSE")  # Default to NSE
        
        if override_token:
            resolved[sym] = {
                "exchange": override_exch,
                "token": override_token,
                "symbol": sym,
            }
            logger.info("Manual override for %s: token=%s, exch=%s", sym, override_token, override_exch)

    # Check if we found all instruments
    missing = [sym for sym in WATCHLIST if sym not in resolved]
    if missing:
        logger.warning("Could not resolve symbols: %s", missing)
        send_telegram(f"⚠️ Could not auto-resolve: {', '.join(missing)}. Check .env TOKEN_* vars.")

    INSTRUMENTS.update(resolved)

    # Telegram dump
    dump_lines = ["📡 Resolved instruments:"]
    for k, v in INSTRUMENTS.items():
        dump_lines.append(f"{k}: exch={v.get('exchange')} token={v.get('token')}")
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
        logger.warning("Symbol %s not in instruments map", symbol)
        return None

    inst = INSTRUMENTS[symbol]
    try:
        # The API expects: exchange, tradingsymbol, symboltoken
        data = s.ltpData(
            exchange=inst["exchange"],
            tradingsymbol=inst["symbol"],  # This should be the exact trading symbol (e.g., "NIFTY", "RELIANCE-EQ")
            symboltoken=inst["token"]
        )
        if data and data.get("status") and data.get("data"):
            return data["data"].get("ltp")
        else:
            logger.error("LTP API error for %s: %s", symbol, data)
            return None
    except Exception as e:
        logger.exception("LTP fetch failed for %s: %s", symbol, e)
    return None

def phase1_loop(s):
    """Every 60s fetch LTP for watchlist."""
    error_count = 0
    max_errors = 5
    
    while True:
        try:
            lines = ["📡 Phase1 LTP Alerts"]
            any_success = False
            
            for sym in WATCHLIST:
                ltp = fetch_ltp(s, sym)
                if ltp is not None:
                    lines.append(f"✅ {sym}: {ltp}")
                    any_success = True
                    error_count = 0  # Reset error count on success
                else:
                    lines.append(f"❌ {sym}: NO_DATA")
            
            if any_success:
                send_telegram("\n".join(lines))
            else:
                error_count += 1
                logger.error("All LTP requests failed (%s/%s)", error_count, max_errors)
                if error_count >= max_errors:
                    send_telegram("🔥 Consecutive errors exceeded. Stopping bot.")
                    break  # Exit the loop
                    
            time.sleep(60)
            
        except Exception as e:
            logger.exception("Error in main loop: %s", e)
            error_count += 1
            time.sleep(30)  # Wait longer on error

if __name__ == "__main__":
    resolve_instruments()
    s = login_smartapi()
    if s:
        phase1_loop(s)
