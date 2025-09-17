# ---------- DIAGNOSTIC: master + REST test (paste at startup, run once) ----------
def instruments_diagnostics_and_rest_tests(jwt_token):
    """
    Download instruments master, show sample rows, auto-resolve desired tokens,
    then test REST LTP and REST candles endpoints for each resolved token.
    Sends results to Telegram (and logs).
    """
    out_lines = []
    try:
        r = requests.get(INSTRUMENTS_URL, timeout=20)
        r.raise_for_status()
        master = r.json()
        out_lines.append(f"MASTER_DOWNLOAD_OK: type={type(master)}")
    except Exception as e:
        logger.exception("MASTER download failed")
        telegram_send_text(f"❌ MASTER download failed: {e}")
        return

    # show a short sample for debugging
    sample = None
    if isinstance(master, dict) and isinstance(master.get("data"), list):
        sample = master["data"][:50]
    elif isinstance(master, list):
        sample = master[:50]
    else:
        sample = [str(master)[:500]]

    # build a small textual sample (avoid huge dumps)
    sample_lines = []
    for i, row in enumerate(sample[:50]):
        if isinstance(row, dict):
            sym = row.get("symbol") or row.get("tradingsymbol") or ""
            exch = row.get("exchange") or ""
            token = row.get("token") or next((v for k,v in row.items() if "token" in k.lower()), None)
            sample_lines.append(f"{i:02d}: {sym} | {exch} | token={token}")
        else:
            sample_lines.append(f"{i:02d}: {str(row)[:140]}")
    telegram_send_text("<b>Instruments master sample (first 50)</b>\n" + "\n".join(sample_lines[:40]))

    # Try to auto-resolve same logic as resolve_instruments_from_master()
    resolved = {}
    wanted_map = {"NIFTY 50": "NIFTY50", "NIFTY50": "NIFTY50", "BANKNIFTY": "BANKNIFTY", "BANK NIFTY": "BANKNIFTY", "SENSEX": "SENSEX", "S&P BSE SENSEX": "SENSEX"}
    rows = master.get("data") if isinstance(master, dict) and isinstance(master.get("data"), list) else (master if isinstance(master, list) else [])
    for row in rows:
        try:
            trad_sym = (row.get("symbol") or row.get("tradingsymbol") or "").strip()
            exch = (row.get("exchange") or row.get("exch") or "").strip()
            token = row.get("token") or row.get("instrument_token") or row.get("symboltoken") or None
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
                for candidate, mapped in wanted_map.items():
                    if candidate.lower() in trad_sym.lower():
                        key = mapped
                        break
            if key and key not in resolved:
                resolved[key] = {"exchange": exch, "symbol": trad_sym, "token": str(token)}
        except Exception:
            continue

    if not resolved:
        telegram_send_text("⚠️ No instruments auto-resolved from master. Master format may differ.")
    else:
        telegram_send_text("<b>Auto-resolved tokens</b>\n" + "\n".join([f"{k}: {v['symbol']} | {v['exchange']} | token={v['token']}" for k,v in resolved.items()]))

    # Try REST LTP & candles for each wanted key (use jwt_token)
    def rest_ltp_for(token, exchange=None):
        try:
            path = f"/rest/marketdata/ltp/v1?exchange={exchange}&symboltoken={token}" if exchange else f"/rest/marketdata/ltp/v1?symboltoken={token}"
            url = BASE_API_HOST.rstrip("/") + path
            headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
            r = requests.get(url, headers=headers, timeout=10)
            return r.status_code, r.text[:2000]
        except Exception as e:
            return None, f"EXC: {e}"

    def rest_candles_for(token):
        try:
            url = BASE_API_HOST.rstrip("/") + "/rest/marketdata/candle/v1"
            headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
            params = {"symboltoken": token, "interval": "5minute"}
            r = requests.get(url, headers=headers, params=params, timeout=20)
            return r.status_code, r.text[:2000]
        except Exception as e:
            return None, f"EXC: {e}"

    # Try for each resolved; if not resolved, also try manual common tokens
    candidates_to_test = {}
    for name in ("NIFTY50", "BANKNIFTY", "SENSEX"):
        if resolved.get(name):
            candidates_to_test[name] = resolved[name]
        else:
            # fallbacks / guesses
            if name == "NIFTY50":
                candidates_to_test[name] = {"exchange": "NSE", "symbol": "NIFTY 50", "token": "99926000"}
            elif name == "BANKNIFTY":
                candidates_to_test[name] = {"exchange": "NSE", "symbol": "BANKNIFTY", "token": "99926009"}
            elif name == "SENSEX":
                candidates_to_test[name] = {"exchange": "BSE", "symbol": "SENSEX", "token": "1"}  # try 99919000 later if fails

    for name, info in candidates_to_test.items():
        token = info.get("token")
        exch = info.get("exchange")
        telegram_send_text(f"<b>Testing {name}</b>\nToken={token} Exchange={exch}")
        st_code, st_text = rest_ltp_for(token, exchange=exch)
        telegram_send_text(f"{name} LTP REST -> status={st_code}\n{st_text}")
        st_code2, st_text2 = rest_candles_for(token)
        telegram_send_text(f"{name} Candles REST -> status={st_code2}\n{st_text2}")

    # additionally try alternate SENSEX token if the first fails
    if "SENSEX" in candidates_to_test:
        alt = "99919000"
        if candidates_to_test["SENSEX"]["token"] != alt:
            telegram_send_text("Trying alternate SENSEX token: " + alt)
            sc, st = rest_ltp_for(alt, exchange="BSE")
            telegram_send_text(f"SENSEX ALT LTP -> status={sc}\n{st}")
            sc2, st2 = rest_candles_for(alt)
            telegram_send_text(f"SENSEX ALT Candles -> status={sc2}\n{st2}")

# call once at startup after login: (in __main__ after obtaining jwt_token)
# instruments_diagnostics_and_rest_tests(jwt_token)
# ---------- end diagnostic ----------
