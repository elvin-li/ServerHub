from __future__ import annotations

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


def discover_vms():
    """UTM + OrbStack Linux machines for status / services feed."""
    try:
        from hub import vms_svc
        return vms_svc.discover_vms()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
