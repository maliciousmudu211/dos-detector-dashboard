# live_predictor_loop.py

import time
import os

while True:
    print("[*] Running live predictor...")
    os.system("sudo /home/ubuntu/myenv/bin/python3 /home/ubuntu/Downloads/live_predictor_combined.py")
    print("[*] Sleeping for 30 seconds before next capture...")
    time.sleep(30)
