"""Kind `responseheaders` (B1): `DefaultResponseHeaders.addDefaultResponseHeaders(response)` of
DefaultResponseHeadersTest (and ServletResponseWriterTest), with the `defaultResponseHeaders` value the instance was
built from. Harvested by the same run as kind `cors` (kinds/cors.py).
"""
import json

from harvest import Kind, control


def convert_responseheaders(case):
    """An expectation answering the recorded response, then a request to it, on a server with the configured
    `defaultResponseHeaders` (its parse and the add-if-absent both show in the answer's headers)."""
    if "unserialisable" in case:
        return None, "unserialisable: " + case["unserialisable"]
    if not case.get("response"):
        return None, "no response"
    return [control("/mockserver/expectation", {"httpRequest": {"path": "/harvested"},
                                                "httpResponse": json.loads(case["response"])}, "response"),
            {"method": "GET", "path": "/harvested", "note": "request"}], None


def responseheaders_properties(case):
    configured = case.get("defaultResponseHeaders")
    return {"defaultResponseHeaders": configured} if configured and configured.strip() else None


KINDS = [Kind("responseheaders", "B1", convert_responseheaders, source=("small", "responseheaders"),
              properties=responseheaders_properties, own_file="-default")]
