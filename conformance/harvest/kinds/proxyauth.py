"""Kind `proxyauth` (B4): `ProxyAuthenticationValidator.isAuthenticated(request, username, password)`."""
import base64

from harvest import Kind, FIELD_VALUE

TARGET = "deadhost.invalid:443"


def convert_proxyauth(case):
    """A `CONNECT` carrying the call's `Proxy-Authorization` values, one header line each, sent as raw bytes to a server
    started with the call's username and password (none when either is blank: nothing is enforced): a 407 refuses it,
    anything else is the tunnel being accepted."""
    if case.get("thrown"):
        return None, "threw " + case["thrown"]
    if case.get("headers") is None:
        return None, "null request"
    lines = ["CONNECT " + TARGET + " HTTP/1.1", "Host: " + TARGET]
    for value in case["headers"]:
        if not FIELD_VALUE.fullmatch(value):
            return None, "header value not valid on the wire"
        lines.append("Proxy-Authorization: " + value)
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    note = "isAuthenticated: " + ("accepted" if case["authenticated"] else "refused") + " by the Java validator"
    return [{"tcp": [base64.b64encode(raw).decode("ascii")], "note": note}], None


def proxyauth_properties(case):
    username, password = case.get("username") or "", case.get("password") or ""
    if not username.strip() or not password.strip():
        return None
    return {"proxyAuthenticationUsername": username, "proxyAuthenticationPassword": password}


KINDS = [Kind("proxyauth", "B4", convert_proxyauth, properties=proxyauth_properties, own_file="-unconfigured")]
