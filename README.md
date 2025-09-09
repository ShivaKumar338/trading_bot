# trading_bot
"""
project_files.py

Generates a GitHub-ready `trading-bot/` folder with all necessary files.
This version fixes previous syntax issues by keeping all embedded Python file
contents inside Python string literals that do NOT contain un-escaped
triple-quote sequences. In particular, the embedded `basic_bot.py` uses
single-line comments instead of triple-quoted docstrings to avoid closing the
outer string literal.

Run:
    python project_files.py

This will write the following files under `./trading-bot/`:
 - README.md
 - requirements.txt
 - .env.example
 - basic_bot.py
 - utils.py
 - tests/test_project_files.py
 - tests/test_basic_helpers.py
"""

from __future__ import annotations
import textwrap
from pathlib import Path
import os
import sys

README_MD = textwrap.dedent("""
# trading-bot

A simplified Binance Futures Testnet trading bot written in Python.

Supports placing MARKET, LIMIT, and STOP_LIMIT orders on the Binance Futures USDT-M Testnet, with logging and CLI utilities.

## Features
- Place MARKET and LIMIT orders (buy/sell).
- Bonus: Supports STOP_LIMIT orders.
- Logs all requests, responses, and errors (logs/basic_bot.log).
- CLI input validation.
- Subcommands to show logs or recent orders.

## Installation
```bash
git clone <your-repo-url>
cd trading-bot
python -m venv venv
# Windows
venv\\Scripts\\activate
# macOS / Linux
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration
Copy `.env.example` to `.env` and update with your Binance Testnet API credentials.
```
cp .env.example .env
```
Set values in `.env`:
```
BINANCE_API_KEY=your_testnet_api_key
BINANCE_API_SECRET=your_testnet_api_secret
```

## Usage
### Place orders
```powershell
# Windows PowerShell example (use 'python' or 'python3' depending on your environment)
python basic_bot.py order --symbol BTCUSDT --side BUY --type MARKET --quantity 0.001 --use-env
```

### Show logs
```powershell
python basic_bot.py logs --tail 200
```

### Show recent orders
```powershell
python basic_bot.py orders --symbol BTCUSDT --limit 5 --use-env
```

## Notes
- Use Binance Futures **Testnet** keys only when testing.
- Do not commit real API keys to git.
""")

REQUIREMENTS_TXT = textwrap.dedent("""
requests
python-dotenv
""")

DOTENV_EXAMPLE = textwrap.dedent("""
BINANCE_API_KEY=your_testnet_api_key
BINANCE_API_SECRET=your_testnet_api_secret
""")

# IMPORTANT: avoid triple-quoted strings inside BASIC_BOT_PY to prevent
# accidental termination of the outer string literal when this script is
# executed from the canvas. Use comments instead of docstrings inside the
# embedded file content.
BASIC_BOT_PY = textwrap.dedent("""
#!/usr/bin/env python3
# basic_bot.py - minimal, import-safe starter for Binance Futures Testnet CLI

import argparse
import hashlib
import hmac
import logging
import os
import sys
import time
from typing import Dict, Any, Optional
import requests
from urllib.parse import urlencode
from dotenv import load_dotenv

# Load .env if present (harmless if not)
load_dotenv()

# Constants
FUTURES_TESTNET_BASE = "https://testnet.binancefuture.com"
ORDER_ENDPOINT = "/fapi/v1/order"
ALL_ORDERS_ENDPOINT = "/fapi/v1/allOrders"
RECV_WINDOW = 5000  # ms

# Logging setup
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "basic_bot.log")

logger = logging.getLogger("basic_bot")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

# File handler
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)

# Console handler
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)


def timestamp_ms() -> int:
    # Return current time in milliseconds
    return int(time.time() * 1000)


def sign_payload(secret: str, payload: str) -> str:
    # Return HMAC-SHA256 hex signature for a given payload and secret
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def send_signed_request(
    api_key: str,
    api_secret: str,
    method: str,
    path: str,
    params: Dict[str, Any],
    base_url: str = FUTURES_TESTNET_BASE,
    timeout: int = 10,
) -> Dict[str, Any]:
    # Send a signed request to Binance Futures Testnet and return parsed JSON.
    headers = {"X-MBX-APIKEY": api_key}
    params = {k: v for k, v in params.items() if v is not None}
    params["timestamp"] = timestamp_ms()
    params.setdefault("recvWindow", RECV_WINDOW)

    query_string = urlencode(params)
    signature = sign_payload(api_secret, query_string)
    signed_qs = f"{query_string}&signature={signature}"
    url = base_url + path

    logger.debug(f"REQUEST -> {method} {url} ? {signed_qs}")
    try:
        if method.upper() == "POST":
            resp = requests.post(url, headers=headers, data=signed_qs, timeout=timeout)
        elif method.upper() == "DELETE":
            resp = requests.delete(url, headers=headers, data=signed_qs, timeout=timeout)
        else:
            # For GET we'll include the full query string in the URL
            resp = requests.get(url + "?" + signed_qs, headers=headers, timeout=timeout)

        logger.debug(f"RESPONSE [{resp.status_code}] {resp.text}")

        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as http_err:
        body = getattr(http_err.response, "text", "")
        logger.error(f"HTTP error: {http_err} | Response: {body}")
        raise
    except Exception as exc:
        logger.exception(f"Error sending request: {exc}")
        raise


ALLOWED_SIDES = {"BUY", "SELL"}
ALLOWED_TYPES = {"MARKET", "LIMIT", "STOP_LIMIT"}
ALLOWED_TIME_IN_FORCE = {"GTC", "IOC", "FOK"}


def validate_args(args: argparse.Namespace):
    # Validate CLI arguments (raises SystemExit with message on error)
    sym = args.symbol.upper()
    if not sym.isalnum():
        raise SystemExit("Invalid symbol format. E.g., BTCUSDT")

    side = args.side.upper()
    if side not in ALLOWED_SIDES:
        raise SystemExit(f"Invalid side: {args.side}. Must be BUY or SELL.")

    otype = args.type.upper()
    if otype not in ALLOWED_TYPES:
        raise SystemExit(f"Invalid order type: {args.type}. Allowed: {', '.join(ALLOWED_TYPES)}")

    try:
        if float(args.quantity) <= 0:
            raise SystemExit("Quantity must be > 0.")
    except Exception:
        raise SystemExit("Quantity must be a valid number > 0.")

    if otype == "LIMIT":
        if args.price is None:
            raise SystemExit("LIMIT orders require --price.")
        if args.time_in_force is None:
            raise SystemExit("LIMIT orders require --time-in-force (GTC/IOC/FOK).")
        if args.time_in_force.upper() not in ALLOWED_TIME_IN_FORCE:
            raise SystemExit("Invalid time-in-force. Choose GTC, IOC, or FOK.")

    if otype == "STOP_LIMIT":
        if args.price is None or args.stop_price is None:
            raise SystemExit("STOP_LIMIT orders require --price and --stop-price.")
        if args.time_in_force is None:
            raise SystemExit("STOP_LIMIT orders require --time-in-force (GTC/IOC/FOK).")


def build_order_params(
    symbol: str,
    side: str,
    otype: str,
    quantity: float,
    price: Optional[float] = None,
    stop_price: Optional[float] = None,
    time_in_force: Optional[str] = None,
) -> Dict[str, Any]:
    # Construct the order parameter dict expected by the Binance Futures API.
    symbol = symbol.upper()
    side = side.upper()
    otype = otype.upper()

    params: Dict[str, Any] = {"symbol": symbol, "side": side, "quantity": quantity}

    if otype == "MARKET":
        params["type"] = "MARKET"
    elif otype == "LIMIT":
        params["type"] = "LIMIT"
        params["price"] = price
        params["timeInForce"] = time_in_force
    elif otype == "STOP_LIMIT":
        params["type"] = "STOP"
        params["price"] = price
        params["stopPrice"] = stop_price
        params["timeInForce"] = time_in_force
    else:
        raise ValueError("Unsupported order type")

    return {k: v for k, v in params.items() if v is not None}


def place_order(api_key: str, api_secret: str, params: Dict[str, Any], base_url: str = FUTURES_TESTNET_BASE) -> Dict[str, Any]:
    # Place an order on Binance Futures Testnet using signed REST call
    try:
        response = send_signed_request(api_key, api_secret, "POST", ORDER_ENDPOINT, params, base_url=base_url)
        logger.info(f"Order placed successfully: {response}")
        return response
    except Exception as exc:
        logger.error(f"Failed placing order: {exc}")
        raise


def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="BasicBot - Binance Futures Testnet order placer")
    sub = p.add_subparsers(dest="cmd")

    # order subcommand
    order_p = sub.add_parser("order")
    order_p.add_argument("--api-key", required=False)
    order_p.add_argument("--api-secret", required=False)
    order_p.add_argument("--symbol", required=True)
    order_p.add_argument("--side", required=True)
    order_p.add_argument("--type", required=True)
    order_p.add_argument("--quantity", required=True)
    order_p.add_argument("--price", required=False)
    order_p.add_argument("--stop-price", dest="stop_price", required=False)
    order_p.add_argument("--time-in-force", dest="time_in_force", required=False)
    order_p.add_argument("--testnet-base-url", dest="base_url", default=FUTURES_TESTNET_BASE)
    order_p.add_argument("--use-env", action="store_true")

    # logs subcommand
    logs_p = sub.add_parser("logs")
    logs_p.add_argument("--tail", type=int, default=100, help="Show last N lines of the log")

    # orders subcommand - fetch recent orders
    orders_p = sub.add_parser("orders")
    orders_p.add_argument("--api-key", required=False)
    orders_p.add_argument("--api-secret", required=False)
    orders_p.add_argument("--symbol", required=True)
    orders_p.add_argument("--limit", type=int, default=5)
    orders_p.add_argument("--use-env", action="store_true")

    return p.parse_args()


def cmd_show_logs(tail: int = 100):
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines[-tail:]:
                print(line.rstrip())
    except FileNotFoundError:
        print("No logs found. Run an order first to generate logs.")


def cmd_show_recent_orders(api_key: str, api_secret: str, symbol: str, limit: int = 5, base_url: str = FUTURES_TESTNET_BASE):
    path = ALL_ORDERS_ENDPOINT
    params = {"symbol": symbol, "limit": limit}
    try:
        data = send_signed_request(api_key, api_secret, "GET", path, params, base_url=base_url)
        for ord in data:
            print(ord)
    except Exception as exc:
        logger.error(f"Failed fetching orders: {exc}")
        print("Failed fetching recent orders. Check your API keys and network.")


def main():
    args = parse_cli_args()

    if args.cmd == "logs":
        cmd_show_logs(tail=args.tail)
        return

    if args.cmd == "orders":
        api_key = args.api_key or (os.getenv("BINANCE_API_KEY") if args.use_env else None)
        api_secret = args.api_secret or (os.getenv("BINANCE_API_SECRET") if args.use_env else None)
        if not api_key or not api_secret:
            print("Missing API credentials. Provide via CLI or set --use-env and environment variables.")
            return
        cmd_show_recent_orders(api_key, api_secret, args.symbol, limit=args.limit)
        return

    # order flow
    api_key = args.api_key or (os.getenv("BINANCE_API_KEY") if args.use_env else None)
    api_secret = args.api_secret or (os.getenv("BINANCE_API_SECRET") if args.use_env else None)
    if not api_key or not api_secret:
        logger.error("Missing API credentials. Abort.")
        print("Missing API credentials. Provide via CLI or set --use-env and environment variables.")
        return

    try:
        validate_args(args)
    except SystemExit as e:
        logger.error(str(e))
        print(str(e))
        return

    params = build_order_params(
        symbol=args.symbol,
        side=args.side,
        otype=args.type,
        quantity=args.quantity,
        price=args.price,
        stop_price=args.stop_price,
        time_in_force=args.time_in_force,
    )

    try:
        result = place_order(api_key, api_secret, params, base_url=args.base_url)
        print("Order response:")
        print(result)
    except Exception:
        print("Order failed. See logs for details.")


if __name__ == "__main__":
    main()
""")

UTILS_PY = textwrap.dedent("""
# utils.py - small helpers reserved for future shared utilities.

def placeholder():
    # This module intentionally left small. Expand as needed for tests and helpers.
    return True
""")

TEST_PROJECT_FILES_PY = textwrap.dedent("""
from pathlib import Path


def test_readme_exists():
    p = Path('trading-bot/README.md')
    assert p.exists(), 'README.md should exist after copying files'
    content = p.read_text(encoding='utf-8')
    assert 'trading-bot' in content
""")

TEST_BASIC_HELPERS_PY = textwrap.dedent("""
import importlib.util
from pathlib import Path


def load_basic_bot_module():
    base = Path(__file__).resolve().parents[1]
    fb = base / 'basic_bot.py'
    spec = importlib.util.spec_from_file_location('basic_bot', str(fb))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_order_market():
    mod = load_basic_bot_module()
    d = mod.build_order_params('BTCUSDT', 'BUY', 'MARKET', 1.23)
    assert d['type'] == 'MARKET'
    assert d['symbol'] == 'BTCUSDT'
    assert d['quantity'] == 1.23


def test_build_order_limit():
    mod = load_basic_bot_module()
    d = mod.build_order_params('ETHUSDT', 'SELL', 'LIMIT', 0.5, price=2000, time_in_force='GTC')
    assert d['type'] == 'LIMIT'
    assert 'price' in d and d['price'] == 2000
    assert d['timeInForce'] == 'GTC'


def test_build_order_stop_limit():
    mod = load_basic_bot_module()
    d = mod.build_order_params('ETHUSDT', 'BUY', 'STOP_LIMIT', 0.1, price=100, stop_price=101, time_in_force='GTC')
    assert d['type'] == 'STOP'
    assert d['stopPrice'] == 101
""")


def write_project_files(base_dir: str = 'trading-bot') -> None:
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)

    (base / 'README.md').write_text(README_MD, encoding='utf-8')
    (base / 'requirements.txt').write_text(REQUIREMENTS_TXT, encoding='utf-8')
    (base / '.env.example').write_text(DOTENV_EXAMPLE, encoding='utf-8')
    (base / 'basic_bot.py').write_text(BASIC_BOT_PY, encoding='utf-8')
    (base / 'utils.py').write_text(UTILS_PY, encoding='utf-8')

    tests_dir = base / 'tests'
    tests_dir.mkdir(parents=True, exist_ok=True)
    (tests_dir / 'test_project_files.py').write_text(TEST_PROJECT_FILES_PY, encoding='utf-8')
    (tests_dir / 'test_basic_helpers.py').write_text(TEST_BASIC_HELPERS_PY, encoding='utf-8')

    print(f'Wrote project files to: {base.resolve()}')


if __name__ == '__main__':
    write_project_files()
