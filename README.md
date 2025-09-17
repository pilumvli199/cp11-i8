# Cleaned SmartAPI Project (Starter)

## Files
- main.py : cleaned login flow (MPIN+TOTP preferred)
- requirements.txt : Python dependencies
- Procfile : run command for platforms (web: python main.py)
- runtime.txt : python runtime pin
- .env.example : environment variables template

## Setup
1. Copy `.env.example` to `.env` and fill real values.
2. Install dependencies: `pip install -r requirements.txt`
3. Run: `python main.py` or deploy to Railway/Heroku.

## Security
- Do NOT commit `.env` with secrets to VCS.
- Store tokens securely after login; don't log secrets.
