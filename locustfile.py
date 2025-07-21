from locust import HttpUser, task, between
import random

class LoadTestUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def test_backend(self):
        # Randomly choose between GET /health and POST /detect
        if random.random() < 0.5:
            self.client.get("/health")
        else:
            headers = {
                "pktcount": str(random.randint(1, 100)),
                "byteperflow": str(random.randint(100, 10000)),
                "tot-kbps": str(random.uniform(0.1, 1000.0)),
                "rx-kbps": str(random.uniform(0.1, 1000.0)),
                "flows": str(random.randint(1, 50)),
                "bytecount": str(random.randint(1000, 100000)),
                "tot-dur": str(random.uniform(0.1, 100.0)),
                "protocol": random.choice(["HTTP", "TCP", "UDP"])
            }
            self.client.post("/detect", headers=headers)
