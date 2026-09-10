import os
import re
import asyncio
import ipaddress
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from telegram import Bot


# ============================================================
# Load configuration
# ============================================================

load_dotenv()

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL")
ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD")
ELASTICSEARCH_CA_CERT = os.getenv("ELASTICSEARCH_CA_CERT")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


# ============================================================
# Detection configuration
# ============================================================

ELASTICSEARCH_INDEX = "game-backend-app-*"

# Alert when the same source IP generates >= 5 SQLi requests
SQLI_THRESHOLD = 5

# Search the last 5 minutes
LOOKBACK = "now-5m"


# ============================================================
# Validate environment variables
# ============================================================

REQUIRED_ENV_VARS = {
    "ELASTICSEARCH_USERNAME": ELASTICSEARCH_USERNAME,
    "ELASTICSEARCH_PASSWORD": ELASTICSEARCH_PASSWORD,
    "ELASTICSEARCH_CA_CERT": ELASTICSEARCH_CA_CERT,
    "TELEGRAM_BOT_TOKEN": TELEGRAM_BOT_TOKEN,
    "TELEGRAM_CHAT_ID": TELEGRAM_CHAT_ID,
}

for name, value in REQUIRED_ENV_VARS.items():
    if not value:
        raise RuntimeError(
            f"{name} is not configured in .env"
        )


# ============================================================
# SQL Injection detection patterns
# ============================================================

SQLI_PATTERNS = [
    # ' OR '1'='1
    r"""['"]\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+""",

    # ' OR username='admin
    r"""['"]\s*(?:or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+""",

    # OR 1=1
    r"""\b(?:or|and)\s+\d+\s*=\s*\d+""",

    # UNION SELECT
    r"""\bunion\s+(?:all\s+)?select\b""",

    # ORDER BY injection
    r"""['"]\s*order\s+by\s+\d+""",

    # SLEEP()
    r"""\bsleep\s*\(\s*\d+\s*\)""",

    # BENCHMARK()
    r"""\bbenchmark\s*\(""",

    # PostgreSQL sleep
    r"""\bpg_sleep\s*\(""",

    # MSSQL WAITFOR DELAY
    r"""\bwaitfor\s+delay\b""",

    # MySQL / PostgreSQL / MSSQL metadata
    r"""\binformation_schema\b""",
    r"""\bsysobjects\b""",
    r"""\bsyscolumns\b""",

    # Stacked queries
    r"""['"]\s*;\s*(?:select|insert|update|delete|drop)\b""",

    # SQL comment after quote
    r"""['"]\s*--\s*$""",
    r"""['"]\s*--\s""",

    # xp_cmdshell
    r"""\bxp_cmdshell\b""",

    # EXEC / EXECUTE
    r"""\bexec(?:ute)?\s*\(""",

    # Classic 1=1
    r"""['"]?\s*1\s*=\s*1\s*(?:--|#|$)""",
]

COMPILED_SQLI_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in SQLI_PATTERNS
]


# ============================================================
# Elasticsearch
# ============================================================

def create_elasticsearch_client():
    """
    Create an authenticated Elasticsearch client using
    the configured CA certificate.
    """

    return Elasticsearch(
        ELASTICSEARCH_URL,
        basic_auth=(
            ELASTICSEARCH_USERNAME,
            ELASTICSEARCH_PASSWORD,
        ),
        ca_certs=ELASTICSEARCH_CA_CERT,
        request_timeout=30,
    )


# ============================================================
# SQLi matching
# ============================================================

def contains_sqli(value):
    """
    Return True if the supplied value contains a SQL injection
    pattern.

    Both the original value and URL-decoded value are checked.
    """

    if value is None:
        return False

    if not isinstance(value, str):
        value = str(value)

    # URL decode things such as:
    # %27 -> '
    # %20 -> space
    decoded = unquote_plus(value)

    values_to_check = {
        value,
        decoded,
    }

    for text in values_to_check:
        for pattern in COMPILED_SQLI_PATTERNS:
            if pattern.search(text):
                return True

    return False


# ============================================================
# Check one Elasticsearch document
# ============================================================

def check_log_sqli(log):
    """
    Check whether an Elasticsearch document contains
    a SQL injection payload.

    Supports:

        1. url.path

        2. Nested:
           http.request.body.username
           http.request.body.password

        3. Flattened:
           http.request.body.username
           http.request.body.password
    """

    # --------------------------------------------------------
    # 1. Check URL path
    # --------------------------------------------------------

    url_path = log.get("url.path")

    if url_path:
        if contains_sqli(url_path):
            print(
                f"[DEBUG] SQLi detected in url.path: "
                f"{url_path!r}"
            )
            return True

    # --------------------------------------------------------
    # 2. Check nested HTTP request body
    #
    # Actual structure from your Elasticsearch:
    #
    # "http.request.body": {
    #     "username": "admin'--",
    #     "password": "..."
    # }
    # --------------------------------------------------------

    body = log.get("http.request.body")

    if isinstance(body, dict):

        for field, value in body.items():

            if contains_sqli(value):
                print(
                    f"[DEBUG] SQLi detected in "
                    f"http.request.body.{field}: {value!r}"
                )
                return True

    # --------------------------------------------------------
    # 3. Check flattened HTTP request body
    #
    # Also supports:
    #
    # "http.request.body.username": "admin'--"
    # --------------------------------------------------------

    body_prefix = "http.request.body."

    for field, value in log.items():

        if field.startswith(body_prefix):

            if contains_sqli(value):
                print(
                    f"[DEBUG] SQLi detected in "
                    f"{field}: {value!r}"
                )
                return True

    return False


# ============================================================
# IP address handling
# ============================================================

def get_source_ip(log):
    """
    Get source IP from the Elasticsearch document.
    """

    return log.get("source.ip")


def normalize_ip(ip):
    """
    Normalize IPv4-mapped IPv6 addresses.

    Example:

        ::ffff:172.18.0.1

    becomes:

        172.18.0.1
    """

    if not ip:
        return None

    try:
        parsed_ip = ipaddress.ip_address(ip)

        # IPv4-mapped IPv6
        if isinstance(parsed_ip, ipaddress.IPv6Address):

            if parsed_ip.ipv4_mapped:
                return str(parsed_ip.ipv4_mapped)

        return str(parsed_ip)

    except ValueError:
        # If the value isn't a valid IP, return it unchanged
        return ip


# ============================================================
# Get recent logs
# ============================================================

def get_recent_logs(es):
    """
    Retrieve logs from the last 5 minutes.
    """

    query = {
        "bool": {
            "filter": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": LOOKBACK,
                            "lte": "now",
                        }
                    }
                }
            ]
        }
    }

    response = es.search(
        index=ELASTICSEARCH_INDEX,
        query=query,
        size=10000,
        sort=[
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ],
    )

    return [
        hit["_source"]
        for hit in response["hits"]["hits"]
    ]


# ============================================================
# Telegram alert
# ============================================================

async def send_telegram_alert(attacker_ip, count):
    """
    Send SQLi alert to Telegram.
    """

    message = (
        "🚨 SQL INJECTION DETECTED 🚨\n\n"
        f"Attacker IP: {attacker_ip}\n"
        f"SQLi requests: {count}\n"
        "Detection window: 5 minutes\n"
        "Severity: HIGH"
    )

    bot = Bot(
        token=TELEGRAM_BOT_TOKEN
    )

    async with bot:
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=message,
        )


# ============================================================
# Main detection logic
# ============================================================

async def main():

    print(
        f"[{datetime.now(timezone.utc).isoformat()}] "
        "Starting SQL injection detection..."
    )

    # --------------------------------------------------------
    # Connect to Elasticsearch
    # --------------------------------------------------------

    es = create_elasticsearch_client()

    if not es.ping():
        raise RuntimeError(
            "Cannot connect to Elasticsearch"
        )

    print(
        "[+] Connected to Elasticsearch"
    )

    # --------------------------------------------------------
    # Retrieve recent logs
    # --------------------------------------------------------

    logs = get_recent_logs(es)

    print(
        f"[+] Retrieved {len(logs)} logs"
    )

    # --------------------------------------------------------
    # Detect SQLi
    # --------------------------------------------------------

    sqli_logs = []

    for log in logs:

        if check_log_sqli(log):
            sqli_logs.append(log)

    print(
        f"[+] Detected {len(sqli_logs)} SQLi logs"
    )

    # --------------------------------------------------------
    # Count SQLi requests per source IP
    # --------------------------------------------------------

    ip_counter = Counter()

    for log in sqli_logs:

        source_ip = get_source_ip(log)

        if not source_ip:
            print(
                "[WARNING] SQLi log has no source.ip"
            )
            continue

        normalized_ip = normalize_ip(
            source_ip
        )

        if normalized_ip:
            ip_counter[normalized_ip] += 1

    # --------------------------------------------------------
    # Print statistics
    # --------------------------------------------------------

    print(
        "\n[*] SQLi events by source IP:"
    )

    if not ip_counter:
        print(
            "    No source IPs found."
        )

    for ip, count in ip_counter.items():

        print(
            f"    {ip}: {count}"
        )

    # --------------------------------------------------------
    # Send Telegram alerts
    # --------------------------------------------------------

    for attacker_ip, count in ip_counter.items():

        if count >= SQLI_THRESHOLD:

            print(
                "\n[!] SQL injection threshold reached!"
            )

            print(
                f"    Attacker IP: {attacker_ip}"
            )

            print(
                f"    SQLi requests: {count}"
            )

            await send_telegram_alert(
                attacker_ip,
                count,
            )

            print(
                "[+] Telegram alert sent"
            )

    print(
        "\n[+] Detection completed."
    )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    asyncio.run(main())

