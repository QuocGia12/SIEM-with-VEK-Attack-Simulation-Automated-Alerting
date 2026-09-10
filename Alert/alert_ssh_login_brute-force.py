import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

from elasticsearch import Elasticsearch
from telegram import Bot


# ==========================================
# Configuration
# ==========================================

ELASTICSEARCH_URL = os.environ.get(
    "ELASTICSEARCH_URL",
    "https://127.0.0.1:9200"
)

ELASTICSEARCH_USERNAME = os.environ.get("ELASTICSEARCH_USERNAME")
ELASTICSEARCH_PASSWORD = os.environ.get("ELASTICSEARCH_PASSWORD")
ELASTICSEARCH_CA_CERT=os.environ.get("ELASTICSEARCH_CA_CERT")

# ELASTICSEARCH_INDEX = os.environ.get(
#     "ELASTICSEARCH_INDEX",
#     "ssh-login-*"
# )

ELASTICSEARCH_INDEX = "ssh-login-*"

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

THRESHOLD = 5
TIME_WINDOW = "5m"


# ==========================================
# Validate configuration
# ==========================================

if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")

if not TELEGRAM_CHAT_ID:
    raise RuntimeError("TELEGRAM_CHAT_ID is not set")


# ==========================================
# Elasticsearch client
# ==========================================

if ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD:
    es = Elasticsearch(
        ELASTICSEARCH_URL,
        basic_auth=(
            ELASTICSEARCH_USERNAME,
            ELASTICSEARCH_PASSWORD,
        ),
        ca_certs=ELASTICSEARCH_CA_CERT,
    )
else:
    es = Elasticsearch(ELASTICSEARCH_URL)


# ==========================================
# Telegram bot
# ==========================================

bot = Bot(token=TELEGRAM_BOT_TOKEN)


# ==========================================
# Elasticsearch query
# ==========================================

def get_failed_logins():
    query = {
        "size": 0,

        "query": {
            "bool": {
                "filter": [
                    {
                        "term": {
                            "event.outcome.keyword": "failure"
                        }
                    },
                    {
                        "range": {
                            "timestamp": {
                                "gte": f"now-{TIME_WINDOW}",
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },

        "aggs": {
            "attackers": {
                "terms": {
                    "field": "source.ip.keyword",
                    "size": 100
                }
            }
        }
    }

    response = es.search(
        index=ELASTICSEARCH_INDEX,
        body=query
    )

    return response["aggregations"]["attackers"]["buckets"]


# ==========================================
# Send Telegram alert
# ==========================================

async def send_telegram_alert(source_ip, count):

    message = (
        "🚨 SSH Login Brute Force Detected\n\n"
        f"Attacker IP: `{source_ip}`\n"
        f"Failed attempts: `{count}`\n"
        f"Time window: `{TIME_WINDOW}`"
    )

    await bot.send_message(
        chat_id=TELEGRAM_CHAT_ID,
        text=message,
        parse_mode="Markdown"
    )


# ==========================================
# Main
# ==========================================

async def main():

    print("Checking SSH login failures...")

    try:
        buckets = get_failed_logins()

    except Exception as e:
        print(f"[ERROR] Elasticsearch query failed: {e}")
        return

    if not buckets:
        print("[INFO] No failed SSH login attempts found.")
        return

    for bucket in buckets:

        source_ip = bucket["key"]
        count = bucket["doc_count"]

        print(
            f"[INFO] {source_ip}: "
            f"{count} failed login attempts"
        )

        if count >= THRESHOLD:

            print(
                f"[ALERT] Brute force detected from {source_ip}"
            )

            try:
                await send_telegram_alert(
                    source_ip,
                    count
                )

                print(
                    f"[INFO] Telegram alert sent for {source_ip}"
                )

            except Exception as e:
                print(
                    f"[ERROR] Failed to send Telegram alert: {e}"
                )


if __name__ == "__main__":
    asyncio.run(main())