#!/bin/sh
# an upstream certificate authority, in the encodings the JDK's X509Factory reads, for
# forwardProxyTLSCustomTrustX509Certificates, and a leaf it signs for the upstream to serve (x509CertificatePath /
# privateKeyPath of a "peer" node). Run from this directory.
#   ca.pem/-key        the CA, PEM, and its key: the peer's certificateAuthorityCertificate/-PrivateKey, because the
#                      oracle refuses an x509CertificatePath leaf its CA certificate did not sign
#   ca.der             the CA, DER
#   ca.p7b             the CA, a DER PKCS#7 bundle (openssl crl2pkcs7)
#   ca-indefinite.der  the CA, BER with indefinite lengths on the certificate and its TBSCertificate
#   upstream.pem/-key  the upstream's leaf (serverAuth) signed by the CA. Host name verification is on under CUSTOM,
#                      so its SANs name every address the forward may reach the peer at: localhost and 127.0.0.1 on
#                      replay, the Docker bridge address (172.17.0.0/23) when recording.
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 36500 -subj "/CN=forward upstream ca" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
  -keyout ca-key.pem -out ca.pem 2> /dev/null
sans="DNS:localhost,IP:127.0.0.1"
for third in 0 1; do
  for fourth in $(seq 0 255); do
    sans="$sans,IP:172.17.$third.$fourth"
  done
done
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' \
  "$sans" > "$work/upstream.ext"
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout upstream-key.pem -out "$work/upstream.csr" 2> /dev/null
openssl x509 -req -in "$work/upstream.csr" -CA ca.pem -CAkey ca-key.pem -set_serial 558 -days 36500 \
  -extfile "$work/upstream.ext" -out upstream.pem 2> /dev/null
chmod 644 ca-key.pem upstream-key.pem # read by the oracle container's user through a bind mount
openssl x509 -in ca.pem -outform DER -out ca.der
openssl crl2pkcs7 -nocrl -certfile ca.pem -outform DER -out ca.p7b
python3 - ca.der ca-indefinite.der << 'PY'
import sys

def header(b, at):
    """(header length, content length) of the definite-length element at `at`."""
    n = b[at + 1]
    if n < 0x80:
        return 2, n
    k = n & 0x7f
    return 2 + k, int.from_bytes(b[at + 2:at + 2 + k], 'big')

def indefinite(b, at, inner):
    """The element at `at` with an indefinite length, its first child too when `inner`."""
    h, n = header(b, at)
    content = b[at + h:at + h + n]
    if inner:
        content = indefinite(content, 0, False) + content[sum(header(content, 0)):]
    return bytes([b[at], 0x80]) + content + b'\0\0'

der = open(sys.argv[1], 'rb').read()
open(sys.argv[2], 'wb').write(indefinite(der, 0, True))
PY
