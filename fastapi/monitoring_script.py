import time
import requests
import psutil
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
FASTAPI_BASE_URL = os.getenv("FASTAPI_BASE_URL", "http://localhost:8000")
DETECT_URL = f"{FASTAPI_BASE_URL}/detect"
HEALTH_URL = f"{FASTAPI_BASE_URL}/health"
INTERVAL = int(os.getenv("MONITOR_INTERVAL", 5))

def check_health():
    try:
        response = requests.get(HEALTH_URL, timeout=3)
        if response.status_code == 200:
            print(f"Health check OK: {response.json()}")
        else:
            print(f"Health check failed with status: {response.status_code}")
    except Exception as e:
        print(f"Health check error: {e}")

def send_test_request():
    test_data = {
        "pktcount": 10,
        "byteperflow": 1000,
        "tot-kbps": 500.5,
        "rx-kbps": 300.3,
        "flows": 5,
        "bytecount": 5000,
        "tot-dur": 10.5,
        "protocol": "HTTP"
    }
    try:
        start = time.time()
        response = requests.post(DETECT_URL, json=test_data, timeout=5)
        duration = time.time() - start
        if response.status_code == 200:
            print(f"Prediction OK: {response.json()} (Response time: {duration:.3f}s)")
        else:
            print(f"Prediction failed with status: {response.status_code}")
    except Exception as e:
        print(f"Prediction request error: {e}")

def monitor_resources():
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    print(f"CPU Usage: {cpu}%, Memory Usage: {mem.percent}%")

def main():
    print("Starting monitoring script. Press Ctrl+C to stop.")
    try:
        while True:
            check_health()
            send_test_request()
            monitor_resources()
            print("-" * 40)
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print("Monitoring stopped by user.")

if __name__ == "__main__":
    main()
