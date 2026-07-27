from __future__ import annotations


def discover_vms():
    """UTM + OrbStack Linux machines for status / services feed."""
    try:
        from hub import vms_svc
        return vms_svc.discover_vms()
    except Exception:
        return []
