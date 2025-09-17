import os
import time
import json
import logging
import requests
import pyotp
import telegram
import pandas as pd
from dotenv import load_dotenv
from SmartApi.smartConnect import SmartConnect

# ------------------- Setup -------------------
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s %(message)s')
load_dotenv()

# Env vars
API_KEY = os.getenv("SMARTAPI_API_KEY")
CLIENT_CODE = os.getenv("SMARTAPI_CLIENT_CODE")
MPIN = os.getenv("SMARTAPI_MPIN")
PASSWORD = os.getenv("SMARTAPI_PASSWORD")
TOTP_SECRET = os.getenv("SMARTAPI_TOTP_SECRET")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)

# ------------------- SmartAPI Init -------------------
totp = pyotp.TOTP(TOTP_SECRET).now()
smart_api = SmartConnect(api_key=API_KEY)

# Login with MPIN + TOTP
try:
    data = smart_api.generateSession(CLIENT_CODE, MPIN, totp)
    if data and data.get("status"):
        logging.info("✅ Login successful!")
        bot.send_message(chat_id=TELEGRAM_CHAT_ID, text="✅ Bot online — LTP monitoring started")
    else:
        logging.error("❌ Login failed: %s", data)
        bot.send_message(chat_id=TELEGRAM_CHAT_ID, text="❌ Login failed, check credentials")
        exit()
except Exception as e:
    logging.error("Login Exception: %s", e)
    bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=f"❌ Login exception: {e}")
    exit()

# ------------------- Instrument Master -------------------
INSTRUMENT_FILE = "instruments.csv"

def download_instruments():
    """Download Angel One instrument master CSV"""
    url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
    logging.info("Downloading instrument master JSON...")
    resp = requests.get(url)
    instruments = resp.json()
    df = pd.DataFrame(instruments)
    df.to_csv(INSTRUMENT_FILE, index=False)
    logging.info("Instrument master saved locally")
    return df

if not os.path.exists(INSTRUMENT_FILE):
    instruments_df = download_instruments()
else:
    instruments_df = pd.read_csv(INSTRUMENT_FILE)

# ------------------- Resolve Token -------------------
def resolve_symbol(symbol, exch):
    """Resolve trading symbol to token"""
    row = instruments_df[
        (instruments_df["symbol"] == symbol) &
        (instruments_df["exch_seg"] == exch)
    ]
    if not row.empty:
        return str(row.iloc[0]["token"])
    return None

WATCHLIST = {
    "NIFTY50": ("NSE", "NIFTY"),
    "BANKNIFTY": ("NSE", "BANKNIFTY"),
    "SENSEX": ("BSE", "SENSEX"),
    "RELIANCE": ("NSE", "RELIANCE"),
    "TCS": ("NSE", "TCS"),
    "HDFCBANK": ("NSE", "HDFCBANK"),
    "INFY": ("NSE", "INFY"),
    "ITC": ("NSE", "ITC")
}

resolved_tokens = {}
for name, (exch, symbol) in WATCHLIST.items():
    token = resolve_symbol(symbol, exch)
    if token:
        resolved_tokens[name] = (exch, token)
        logging.info(f"[INSTR] Resolved {name} -> token={token} exch={exch}")
    else:
        logging.warning(f"[INSTR] Could not resolve {name} ({exch}:{symbol})")

# ------------------- Fetch LTP -------------------
def fetch_ltp(symbol, exch, token):
    try:
        data = smart_api.ltpData(exchange=exch, tradingsymbol=symbol, symboltoken=str(token))
        if data and data.get("data"):
            return data["data"]["ltp"]
        return None
    except Exception as e:
        logging.error(f"LTP fetch error for {symbol}: {e}")
        return None

# ------------------- Monitoring Loop -------------------
POLL_INTERVAL = 60  # seconds

while True:
    msg_lines = ["📡 LTP Update"]
    for name, (exch, token) in resolved_tokens.items():
        ltp = fetch_ltp(name, exch, token)
        if ltp:
            line = f"✅ {name}: {ltp}"
        else:
            line = f"❌ {name}: NO_DATA"
        msg_lines.append(line)
    final_msg = "\n".join(msg_lines)
    bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=final_msg)
    logging.info("Sent update to Telegram")
    time.sleep(POLL_INTERVAL)
