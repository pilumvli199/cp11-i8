#!/usr/bin/env python3
"""Cleaned SmartAPI starter - login and token handling (minimal).
- Does MPIN+TOTP login (preferred) or Password+TOTP fallback.
- Uses environment variables (see .env.example).
- Does NOT log tokens or secrets.
"""
import os, sys, time, datetime, traceback, importlib, logging
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

SMARTAPI_API_KEY = os.getenv('SMARTAPI_API_KEY','').strip()
SMARTAPI_CLIENT_CODE = os.getenv('SMARTAPI_CLIENT_CODE','').strip()
SMARTAPI_MPIN = os.getenv('SMARTAPI_MPIN','').strip()
SMARTAPI_PASSWORD = os.getenv('SMARTAPI_PASSWORD','').strip()
SMARTAPI_TOTP_SECRET = os.getenv('SMARTAPI_TOTP_SECRET','').strip()

# import SmartConnect flexibly
SmartConnect = None
for name in ('smartapi','SmartApi','smartapi_python'):
    try:
        mod = importlib.import_module(name)
        if hasattr(mod,'SmartConnect'):
            SmartConnect = getattr(mod,'SmartConnect')
            break
        # sometimes package exposes class in submodule
        if hasattr(mod,'smartConnect') and hasattr(mod.smartConnect,'SmartConnect'):
            SmartConnect = getattr(mod.smartConnect,'SmartConnect')
            break
    except Exception:
        continue

if SmartConnect is None:
    logger.error('SmartConnect could not be imported. Ensure smartapi-python is installed.')
    sys.exit(1)

try:
    s = SmartConnect(api_key=SMARTAPI_API_KEY)
except TypeError:
    s = SmartConnect(SMARTAPI_API_KEY)
except Exception:
    logger.exception('SmartConnect init failed')
    sys.exit(1)

try:
    import pyotp
except Exception:
    pyotp = None

def totp_candidates(secret):
    if not pyotp or not secret:
        return []
    epoch = int(time.time())
    codes = []
    for offset in (-30,0,30):
        try:
            codes.append(str(pyotp.TOTP(secret).at(epoch+offset)).zfill(6))
        except Exception:
            codes.append(None)
    # unique order preserved
    out = []
    seen = set()
    for c in codes:
        if c and c not in seen:
            out.append(c); seen.add(c)
    return out

def try_login_mpin(max_retries=3):
    if not SMARTAPI_MPIN or not SMARTAPI_TOTP_SECRET:
        return None
    candidates = totp_candidates(SMARTAPI_TOTP_SECRET)
    attempt = 0
    while attempt < max_retries:
        for code in candidates:
            if not code: continue
            try:
                resp = s.generateSession(SMARTAPI_CLIENT_CODE, SMARTAPI_MPIN, code)
                if isinstance(resp, dict) and resp.get('status'):
                    return resp
            except Exception as e:
                err = str(e).lower()
                if 'exceeding access rate' in err or 'access denied' in err:
                    time.sleep(2**attempt)
                else:
                    time.sleep(1)
        attempt += 1
    return None

def try_login_password_totp():
    if not SMARTAPI_PASSWORD or not SMARTAPI_TOTP_SECRET:
        return None
    if not pyotp:
        logger.warning('pyotp not available for TOTP generation')
        return None
    candidates = totp_candidates(SMARTAPI_TOTP_SECRET)
    for code in candidates:
        if not code: continue
        try:
            resp = s.generateSession(SMARTAPI_CLIENT_CODE, SMARTAPI_PASSWORD, code)
            if isinstance(resp, dict):
                msg = str(resp.get('message','')).lower()
                if 'loginbypassword is not allowed' in msg or 'switch to login by mpin' in msg:
                    return resp
                if resp.get('status'):
                    return resp
        except Exception as e:
            err = str(e).lower()
            if 'exceeding access rate' in err or 'access denied' in err:
                time.sleep(2)
            else:
                time.sleep(1)
    return None

def main():
    logger.info('Starting login flow at %s', datetime.datetime.utcnow().isoformat())
    if not SMARTAPI_CLIENT_CODE:
        logger.error('SMARTAPI_CLIENT_CODE missing (set in .env)')
        sys.exit(1)

    resp = try_login_mpin(max_retries=4)
    if resp and isinstance(resp, dict) and resp.get('status'):
        logger.info('MPIN login successful')
        # TODO: securely persist tokens and continue bot logic
        return

    resp2 = try_login_password_totp()
    if resp2 and isinstance(resp2, dict) and resp2.get('status'):
        logger.info('Password+TOTP login successful')
        return

    logger.error('Login failed. MPIN resp=%s pwd+totp resp=%s', resp, resp2)
    sys.exit(1)

if __name__ == '__main__':
    main()
