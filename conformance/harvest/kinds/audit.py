"""Kind `audit` (B4): the control-plane audit tests (`HttpStateAuditTest`, `HttpStateAuditEndpointTest`)
through HttpState.handle, converted as kind `handle` from a run of their own: the run writes
target/harvest-b4/audit/handle.jsonl, and the files are B4-audit-<Class>-<label>.json. The tests read the process-wide
`AuditStore` directly, so each case ends with `GET /mockserver/audit`, which shows the same store on the wire.
`AuditStoreTest` and `AuditFileSinkTest` build their own store and sink around hand-made entries: no wire form."""
import importlib.util
import os

from harvest import Kind

_spec = importlib.util.spec_from_file_location("harvest_kinds_handle_for_audit", os.path.join(os.path.dirname(__file__), "handle.py"))
_handle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_handle)


AUDIT_MASK = ["\"epochTimeMs\" ?: ?\\d+", "\"sourceAddress\" ?: ?\"[^\"]*\"", "content-length: \\d+"]


def convert_audit(case):
    steps, reason = _handle.convert_handle(case)
    if steps is None:
        return None, reason
    steps = steps + [{"method": "GET", "path": "/mockserver/audit", "note": "the audit store (AuditStore.getRecent)"}]
    for step in steps:
        if step["path"].split("?")[0] in ("/mockserver/audit", "/audit"):
            # the entry's time and the client's address as the server saw it (Docker's gateway for the oracle)
            step["mask"] = AUDIT_MASK
    return steps, None


KINDS = [Kind("audit", "B4", convert_audit, source=("audit", "handle"), group=_handle.group_handle,
              properties=_handle.handle_properties, per_test=True, own_file="-default")]
