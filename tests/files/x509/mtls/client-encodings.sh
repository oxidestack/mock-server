#!/bin/sh
# client.pem in the encodings a forward-proxy client certificate chain file may come in. Derived from
# client.pem only (no new keys), so it can run after gen.sh or on its own. Run from this directory.
#   client.der                 DER
#   client.p7b                 a DER PKCS#7 bundle (openssl crl2pkcs7)
#   client-p7b.pem             the same bundle, PEM (-----BEGIN PKCS7-----)
#   client-indefinite.der      BER with indefinite lengths on the certificate and its TBSCertificate
#   client-indefinite.pem      the same BER, PEM-armoured as a CERTIFICATE
set -eu
openssl x509 -in client.pem -outform DER -out client.der
openssl crl2pkcs7 -nocrl -certfile client.pem -outform DER -out client.p7b
openssl crl2pkcs7 -nocrl -certfile client.pem -outform PEM -out client-p7b.pem
python3 - client.der client-indefinite.der client-indefinite.pem << 'PY'
import base64, sys

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

ber = indefinite(open(sys.argv[1], 'rb').read(), 0, True)
open(sys.argv[2], 'wb').write(ber)
text = base64.b64encode(ber).decode()
lines = [text[i:i + 64] for i in range(0, len(text), 64)]
open(sys.argv[3], 'w').write('-----BEGIN CERTIFICATE-----\n' + '\n'.join(lines) + '\n-----END CERTIFICATE-----\n')
PY
