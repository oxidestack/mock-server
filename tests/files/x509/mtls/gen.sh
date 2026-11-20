#!/bin/sh
# a control-plane CA chain in three encodings the JDK's X509Factory reads, and client certificates to
# present against it. Run from this directory; the CA keys are thrown away.
#   ca.pem             the CA, PEM
#   ca.der             the CA, DER
#   ca.p7b             the CA, a DER PKCS#7 bundle (openssl crl2pkcs7)
#   ca-indefinite.der  the CA, BER with indefinite lengths on the certificate and its TBSCertificate
#   client.pem/-key    a client certificate (clientAuth) signed by the CA
#   foreign.pem/-key   a client certificate signed by another CA
#   bundled-ca.der     MockServer's bundled CA (src/tls/CertificateAuthorityCertificate.pem), DER
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ext="$work/client.ext"
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > "$ext"
for ca in ca foreign-ca; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 36500 -subj "/CN=control plane $ca" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$work/$ca-key.pem" -out "$work/$ca.pem" 2> /dev/null
done
issue() { # name ca
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$1-key.pem" -out "$work/$1.csr" 2> /dev/null
  openssl x509 -req -in "$work/$1.csr" -CA "$work/$2.pem" -CAkey "$work/$2-key.pem" -CAcreateserial -days 36500 \
    -extfile "$ext" -out "$1.pem" 2> /dev/null
}
issue client ca
issue foreign foreign-ca
cp "$work/ca.pem" ca.pem
openssl x509 -in "$work/ca.pem" -outform DER -out ca.der
openssl crl2pkcs7 -nocrl -certfile "$work/ca.pem" -outform DER -out ca.p7b
openssl x509 -in ../../../../src/tls/CertificateAuthorityCertificate.pem -outform DER -out bundled-ca.der
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
./client-encodings.sh
