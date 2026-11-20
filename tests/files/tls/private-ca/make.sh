#!/bin/sh
# a private test CA for the mTLS scenarios, so that no client certificate or trusted CA list of theirs
# chains to MockServer's bundled CA (tests/files/tls/fwd-ca.pem), which 9.1.0 never trusts for mTLS (upstream #227,
# #230). Each leaf mirrors the bundled-CA fixture it replaced (removed then, except fwd-client, still used by
# src/tls/mod.rs and a process scenario): same subject, extensions and validity.
#   ca              "O=Fixture, CN=Private Test CA", CA:TRUE, keyCertSign, a subject key identifier
#   no-eku          tests/files/auth/mtls-no-eku-cert.pem       (no extended key usage)
#   any-eku         tests/files/auth/mtls-any-eku-cert.pem      (anyExtendedKeyUsage)
#   expired         tests/files/auth/mtls-expired-cert.pem      (clientAuth, expired 2026-09-04)
#   forward-client  tests/files/tls/fwd-client-cert.pem         (clientAuth, key identifiers)
#   dirname-client  tests/files/tls/dirname-client-cert.pem     (clientAuth, key identifiers, directory-name SANs)
# Keys are unencrypted PKCS#8 PEM. Run from anywhere with openssl 3.4+; it rewrites every file here, CA included, so
# run tests/files/asyncapi/mqtt-ssl/key-choice/make.sh after it (its stores are issued by this CA).
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1-key.pem" 2>/dev/null; }

key ca
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=none\n' \
  > "$work/ca.ext"
openssl req -new -key ca-key.pem -subj "/O=Fixture/CN=Private Test CA" -out "$work/ca.csr"
openssl x509 -req -in "$work/ca.csr" -key ca-key.pem -set_serial 0x2001 -not_before 20261003000000Z \
  -not_after 21260910000000Z -extfile "$work/ca.ext" -out ca-cert.pem 2>/dev/null

leaf() { # name subject serial not_before not_after extensions
  key "$1"
  printf '%b' "$6" > "$work/$1.ext"
  openssl req -new -key "$1-key.pem" -subj "$2" -out "$work/$1.csr"
  openssl x509 -req -in "$work/$1.csr" -CA ca-cert.pem -CAkey ca-key.pem -set_serial "$3" -not_before "$4" \
    -not_after "$5" -extfile "$work/$1.ext" -out "$1-cert.pem" 2>/dev/null
}

bare='subjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n'
leaf no-eku "/O=Fixture/CN=no-eku.example" 0x2002 20261003000000Z 21260910000000Z \
  "basicConstraints=critical,CA:FALSE\n$bare"
leaf any-eku "/O=Fixture/CN=any-eku.example" 0x2003 20261003000000Z 21260910000000Z \
  "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=anyExtendedKeyUsage\n$bare"
leaf expired "/O=Fixture/CN=expired.example" 0x2004 20250830000000Z 20260904000000Z \
  "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n$bare"
leaf forward-client "/CN=forward-client.example/O=Fixture" 0x2005 20261002105334Z 21260908105334Z \
  'extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'
# The subject alternative names of tests/files/tls/dirname-client-cert.pem, byte for byte (DNS:dns.example and two
# directory names with escaped, multi-valued and custom-OID attributes, as client_cert_directory_name_san prints them).
san=30820132820B646E732E6578616D706C65A47E307C310B30090603550406130247423110300E06035504080C07456E676C616E64311230
san=${san}10060355040A0C0941636D652C20496E6331123010060355040B0C09556E69742B506C75733113301106035504030C0A4469723D4E
san=${san}616D653B78311E301C06092A864886F70D010901160F646972406578616D706C652E636F6DA481A230819F31173015060A0992268993
san=${san}F22C64011916076578616D706C6531133011060A0992268993F22C6401191603636F6D31153013060A0992268993F22C6401010C0575
san=${san}73657231310E300C0603550405130531323334353112301006035504090C0931204D61696E205374310E300C06035504070C054C6565
san=${san}6473310F300D06032A03040C06637573746F6D3113301106035504030C0A7365636F6E6420646972
leaf dirname-client "/O=Fixture/CN=dirname-client.example" 0x2006 20261004124105Z 21260910124105Z \
  "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n2.5.29.17=DER:$san\n"
