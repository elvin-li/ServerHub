"""Probe 2: lying __class__, str.split liar, rc eq-bombs, epoch/duration bombs."""
import os, tempfile
_root = tempfile.mkdtemp(prefix="jobs8-probe-")
os.environ.setdefault("SERVERHUB_STATE_DIR", os.path.join(_root, "state"))
os.environ["HOME"] = os.path.join(_root, "home")
os.makedirs(os.environ["HOME"], exist_ok=True)

from unittest import mock
from fastapi.testclient import TestClient
from hub.app_factory import create_app
from hub.auth import require_auth
from hub import scheduler_svc
from hub import jobs as hub_jobs

app = create_app()
app.dependency_overrides[require_auth] = lambda: True
client = TestClient(app, raise_server_exceptions=False)


def liar(claim):
    class Liar:
        @property
        def __class__(self):
            return claim
        def __hash__(self):
            return 1
    return Liar()


class EqBombInt(int):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")
    __ne__ = __eq__
    def __hash__(self):
        return 0


class FloatBomb(float):
    def __float__(self):
        raise RuntimeError("float bomb")
    def __eq__(self, other):
        raise RuntimeError("eq bomb")
    __ne__ = __eq__
    def __hash__(self):
        return 0


def report(label, r):
    print(f"{label}: {r.status_code} {r.text[:100]!r}")


# A. bool-liar as a maintenance value → _jsonable returns it raw → dumps TypeError?
rows = [{"id": "ok", "desc": liar(bool), "command": "true"}]
with mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows}):
    report("maint bool-liar desc", client.get("/api/maintenance"))

# B. bytes-liar as a maintenance value → _decode_bytes TypeError?
rows = [{"id": "ok", "desc": liar(bytes), "command": "true"}]
with mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows}):
    report("maint bytes-liar desc", client.get("/api/maintenance"))

# C. str-liar (should be immune via str.encode TypeError caught)
rows = [{"id": "ok", "desc": liar(str), "command": "true"}]
with mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows}):
    report("maint str-liar desc", client.get("/api/maintenance"))

good = {"id": "good", "name": "n", "type": "command", "cron": "* * * * *",
        "enabled": True, "params": {"command": "true"}}
def sched(rows):
    return mock.patch.object(scheduler_svc, "cfg", lambda: {"schedules": rows})

# D. scheduler bool-liar / bytes-liar values
with sched([dict(good, id="b", name=liar(bool)), good]):
    report("sched bool-liar name", client.get("/api/scheduler/jobs"))
with sched([dict(good, id="b", name=liar(bytes)), good]):
    report("sched bytes-liar name", client.get("/api/scheduler/jobs"))

# E. str-liar cron → str.split(liar) TypeError out of _cron_field_tokens?
with sched([dict(good, id="b", cron=liar(str)), good]):
    report("sched str-liar cron", client.get("/api/scheduler/jobs"))

# F. str-liar enabled → str.strip(liar) TypeError out of job_enabled?
with sched([dict(good, id="b", enabled=liar(str)), good]):
    report("sched str-liar enabled", client.get("/api/scheduler/jobs"))

# G. bool-liar enabled → returned raw from job_enabled?
ran = []
with sched([dict(good, id="b", enabled=liar(bool)), good]), \
        mock.patch.object(scheduler_svc, "_execute",
                          lambda job, trigger: ran.append(scheduler_svc._job_id(job))), \
        mock.patch.object(scheduler_svc, "_last_minute", None):
    try:
        print("tick bool-liar enabled: launched=", scheduler_svc._tick_once())
    except Exception as e:
        print(f"tick bool-liar enabled: ABORTED {type(e).__name__}: {e}")

# H. float-subclass eq-bomb rc in a leftover _jobs row
hub_jobs._jobs["ok"] = {"running": False, "rc": FloatBomb(1.0), "finished": None}
with mock.patch.object(hub_jobs, "cfg",
                       lambda: {"maintenance": [{"id": "ok", "command": "true"}]}):
    report("maint float-eq-bomb rc", client.get("/api/maintenance"))
hub_jobs._jobs.clear()

# I. _execute with a runner returning an int-subclass eq-bomb rc
job = dict(good, id="rcbomb")
with mock.patch.dict(scheduler_svc._RUNNERS, {"command": lambda j, log: EqBombInt(1)}):
    try:
        entry = scheduler_svc._execute(job, "manual")
        print("execute rc eq-bomb: entry status=", entry.get("status"))
    except Exception as e:
        print(f"execute rc eq-bomb: RAISED {type(e).__name__}: {e}")

# J. _epoch_int / _finite_duration with float-subclass bombs (leftover clock)
try:
    print("epoch_int float-eq-bomb:", scheduler_svc._epoch_int(FloatBomb(2.0)))
except Exception as e:
    print(f"epoch_int float-eq-bomb: RAISED {type(e).__name__}: {e}")
try:
    print("finite_duration bomb:", scheduler_svc._finite_duration(FloatBomb(2.0), 1.0))
except Exception as e:
    print(f"finite_duration bomb: RAISED {type(e).__name__}: {e}")

# K. class-bomb timeout through jobs._clamp_timeout (run_watchdog seam)
class ClassBomb:
    @property
    def __class__(self):
        raise RuntimeError("class access bomb")
try:
    print("clamp_timeout class bomb:", hub_jobs._clamp_timeout(ClassBomb()))
except Exception as e:
    print(f"clamp_timeout class bomb: RAISED {type(e).__name__}: {e}")
try:
    print("clamp_timeout float-eq-bomb:", hub_jobs._clamp_timeout(FloatBomb(5.0)))
except Exception as e:
    print(f"clamp_timeout float-eq-bomb: RAISED {type(e).__name__}: {e}")
