"""Kind `proxysetup` (B4): `new ProxySetupInfo(caCertificatePath, ports, configuration, osName)`, what
`GET /mockserver/proxyConfiguration` renders."""
from harvest import Kind

DIRECTORY = "/tmp/mock-server-B4-proxysetup"


def directory(case):
    flags = [name for name in ("dynamicallyCreateCertificateAuthorityCertificate", "proxySetup") if case.get(name) == "true"]
    return DIRECTORY + "".join("-" + ("dynamic" if f.startswith("dynamically") else "flag") for f in flags)


def convert_proxysetup(case):
    """`GET /mockserver/proxyConfiguration` as JSON and as text on a server started with the configuration's values.
    The server passes its own port and the OS it runs on, so only a single port and a non-Windows OS (the oracle runs
    on Linux) are reachable; the CA path is masked (it is the server's own), as is a freshly minted CA."""
    if len(case.get("ports") or []) != 1:
        return None, "ports %s: the server passes exactly its own port" % case.get("ports")
    if "win" in (case.get("osName") or "").lower():
        return None, "Windows OS (the oracle runs on Linux)"
    if case.get("certificateAuthorityCertificate") != case.get("defaultCertificateAuthorityCertificate"):
        return None, "custom certificateAuthorityCertificate (a path naming no file)"
    path = directory(case).replace(".", "\\.") + "/mockserver-ca\\.pem"
    pem = "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
    return [
        {"method": "GET", "path": "/mockserver/proxyConfiguration", "note": "json", "mask": [path, ":\\d+\\\"", pem]},
        {"method": "GET", "path": "/mockserver/proxyConfiguration", "headers": {"Accept": "text/plain"}, "note": "text",
         "mask": [path]},
    ], None


def proxysetup_properties(case):
    props = {"directoryToSaveDynamicSSLCertificate": directory(case)}
    for name in ("dynamicallyCreateCertificateAuthorityCertificate", "proxySetup"):
        if case.get(name) == "true":
            props[name] = "true"
    return props


KINDS = [Kind("proxysetup", "B4", convert_proxysetup, properties=proxysetup_properties)]
