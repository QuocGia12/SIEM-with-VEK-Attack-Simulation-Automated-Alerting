#!/usr/bin/env python3

import subprocess
import time

TARGET = "" # ip of target 
USERNAME = "" # username to brute force password
ATTEMPTS = 20
DELAY = 0.2

for i in range(ATTEMPTS):
    print(f"[{i + 1}/{ATTEMPTS}] Trying SSH login...")

    subprocess.run(
        [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=2",
            f"{USERNAME}@{TARGET}",
        ],
        input="DefinitelyWrongPassword\n",
        text=True,
        capture_output=True,
    )

    time.sleep(DELAY)

print("Simulation finished.")