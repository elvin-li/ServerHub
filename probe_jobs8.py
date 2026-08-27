"""Probe: __class__-property bombs across jobs/scheduler surfaces (jobs8 hunt)."""
import os, tempfile
_root = tempfile.mkdtemp(prefix="jobs8-probe-")
os.environ.setdefault("SERVERHUB_STATE_DIR", os.path.join(_root, "state"))
os.environ["HOME"] = os.path.join(_root, "home")
os.makedirs(os.environ["HOME"], exist_ok=True)

from unittest import mock
from fastapi.testclient import TestClient
from hub.app_factory import create_app
from hub.auth import require_auth
from hub import scheduler_svc, audit
from hub import jobs as hub_jobs

app = create_app()
app.dependency_overrides[require_auth] = lambda: True
client = TestClient(app, raise_server_exceptions=False)


class ClassBomb:
    @property
    def __class__(self):
        raise RuntimeError("class access bomb")
    def __hash__(self):
        return 1


class DictClassBomb(dict):
    @property
    def __class__(self):
        raise RuntimeError("dict class bomb")


def report(label, r):
    print(f"{label}: {r.status_code} {r.text[:120]!r}")


# 1. maintenance row value bomb (desc)
rows = [{"id": "ok", "name": "fine", "desc": ClassBomb(), "command": "true"}]
with mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows}):
    report("maint desc value bomb", client.get("/api/maintenance"))

# 2. maintenance row id bomb
rows = [{"id": ClassBomb(), "command": "true"}, {"id": "ok", "command": "true"}]
with mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows}):
    report("maint id bomb", client.get("/api/maintenance"))

# 3. whole maintenance row bomb (non-dict with class bomb)
rows = [ClassBomb(), {"id": "ok", "command": "true"}]
with mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows}):
    report("maint whole-row bomb", client.get("/api/maintenance"))

# 3b. dict-subclass row with __class__ bomb
rows = [DictClassBomb(id="sub", command="true"), {"id": "ok", "command": "true"}]
with mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows}):
    report("maint dict-subclass-classbomb row", client.get("/api/maintenance"))

# 4. POST run over the same poisoned cfg
rows = [ClassBomb(), {"id": "ok", "command": "true"}]
with mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows}), \
        mock.patch.object(audit, "record", lambda e, **f: {}):
    report("maint run over row bomb", client.post("/api/maintenance/ok/run"))
hub_jobs._jobs.clear()

# 5. leftover _jobs row with bomb rc
rows = [{"id": "ok", "command": "true"}]
hub_jobs._jobs["ok"] = {"running": False, "rc": ClassBomb(), "finished": None}
with mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows}):
    report("maint job_state rc bomb", client.get("/api/maintenance"))
report("maint log rc bomb", client.get("/api/maintenance/ok/log"))

# 6. leftover _jobs row with bomb log entry
hub_jobs._jobs["ok"] = {"running": False, "rc": 0, "log": ["fine", ClassBomb()]}
report("maint log entry bomb", client.get("/api/maintenance/ok/log"))
hub_jobs._jobs.clear()

# 7. scheduler job id bomb
def sched(rows):
    return mock.patch.object(scheduler_svc, "cfg", lambda: {"schedules": rows})

good = {"id": "good", "name": "n", "type": "command", "cron": "* * * * *",
        "enabled": True, "params": {"command": "true"}}
with sched([dict(good, id=ClassBomb()), good]):
    report("sched id bomb", client.get("/api/scheduler/jobs"))

# 8. scheduler enabled bomb
with sched([dict(good, id="bombed", enabled=ClassBomb()), good]):
    report("sched enabled bomb", client.get("/api/scheduler/jobs"))

# 9. scheduler cron bomb (next_run_ts path)
with sched([dict(good, id="bombed", cron=ClassBomb()), good]):
    report("sched cron bomb", client.get("/api/scheduler/jobs"))

# 10. scheduler name / params value bomb (jsonable path)
with sched([dict(good, id="bombed", name=ClassBomb()), good]):
    report("sched name bomb", client.get("/api/scheduler/jobs"))
with sched([dict(good, id="bombed", params={"command": "true", "x": ClassBomb()}), good]):
    report("sched params value bomb", client.get("/api/scheduler/jobs"))

# 11. mapping key bomb in params
with sched([dict(good, id="bombed", params={ClassBomb(): "v"}), good]):
    report("sched params key bomb", client.get("/api/scheduler/jobs"))

# 12. tick abort: bombed sibling vs healthy
for label, bad in [
    ("tick id bomb", dict(good, id=ClassBomb())),
    ("tick enabled bomb", dict(good, id="bombed", enabled=ClassBomb())),
    ("tick cron bomb", dict(good, id="bombed", cron=ClassBomb())),
]:
    ran = []
    with sched([bad, good]), \
            mock.patch.object(scheduler_svc, "_execute",
                              lambda job, trigger: ran.append(scheduler_svc._job_id(job))), \
            mock.patch.object(scheduler_svc, "_last_minute", None):
        try:
            launched = scheduler_svc._tick_once()
            print(f"{label}: launched={launched}")
        except Exception as e:
            print(f"{label}: TICK ABORTED {type(e).__name__}: {e}")

# 13. mutations on healthy job with bomb sibling row (whole-row bomb in schedules)
with sched([ClassBomb(), good]):
    report("sched delete w/ row bomb sibling", client.delete("/api/scheduler/jobs/good"))
with sched([ClassBomb(), good]):
    report("sched run-now w/ row bomb sibling", client.post("/api/scheduler/jobs/good/run-now"))

# 14. start_job with bomb-id task (tools_svc seam)
try:
    hub_jobs.start_job({"id": ClassBomb(), "command": "true"})
    print("start_job bomb id: returned")
except Exception as e:
    print(f"start_job bomb id: RAISED {type(e).__name__}: {e}")
hub_jobs._jobs.clear()
