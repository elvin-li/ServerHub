"""Time every step the FastAPI lifespan performs at startup."""
import sys
import time

sys.path.insert(0, ".")

from hub import alerts, metrics, network_svc, tools_svc
from hub.config import cfg

s = cfg().get("settings") or {}


def step(label, fn):
    t0 = time.time()
    try:
        fn()
        ms = (time.time() - t0) * 1000
    except Exception as exc:
        ms = (time.time() - t0) * 1000
        print(f"  {label:34} {ms:8.1f} ms   ({type(exc).__name__})")
        return ms
    flag = "  <-- BLOCKS STARTUP" if ms > 200 else ""
    print(f"  {label:34} {ms:8.1f} ms{flag}")
    return ms


print("=== lifespan startup steps ===")
total = 0
total += step("metrics.start_sampler", lambda: metrics.start_sampler(int(s.get("metrics_interval") or 90)))
total += step("alerts.start_alerter", lambda: alerts.start_alerter(int(s.get("alert_interval") or 90)))
total += step("tools_svc.start_updates_warmer", tools_svc.start_updates_warmer)
total += step("network_svc.start_alias_autobind", network_svc.start_alias_autobind)
print(f"\n  total blocking startup work      {total:8.1f} ms")

# Leave nothing running behind us.
metrics.stop_sampler()
alerts.stop_alerter()
tools_svc.stop_updates_warmer()
network_svc.stop_alias_autobind()
print("  (all background workers stopped)")
