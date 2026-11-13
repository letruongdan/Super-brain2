"""CI diagnostic: how far timed waits overshoot on this runner (Thread.join, Event.wait, sleep) for several timeouts."""

import threading
import time

hold = threading.Event()
worker = threading.Thread(target=hold.wait, daemon=True)
worker.start()
for timeout in (0.001, 0.005, 0.010, 0.025, 0.050):
    for name, wait in (
        ("join", lambda t: worker.join(t)),
        ("event", lambda t: threading.Event().wait(t)),
        ("sleep", time.sleep),
    ):
        overs = []
        for _ in range(10):
            t0 = time.perf_counter()
            wait(timeout)
            overs.append((time.perf_counter() - t0 - timeout) * 1000)
        overs.sort()
        print(f"{name:5s} timeout={timeout * 1000:5.1f}ms overshoot ms min={overs[0]:.2f} p50={overs[5]:.2f} max={overs[-1]:.2f}")
hold.set()
