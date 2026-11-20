#!/bin/sh
# client certificates that 9.1.0's leaf-only control-plane mTLS (upstream #227, eef1d8e8b) and its
# bundled-CA refusal (#227, #230, cb3817ce3) must refuse, beside one that must pass. Issued from the private test CA one
# directory up (../ca-cert.pem, ../ca-key.pem), which this script reads but never rewrites.
#   attacker-ca          "CN=Attacker CA", CA:TRUE
#   attacker             clientAuth leaf signed by attacker-ca;   attacker-chain.pem = attacker + the trusted CA
#   self-signed          clientAuth leaf signed by its own key;   self-signed-chain.pem = self-signed + the trusted CA
#   ca-leaf              CA:TRUE certificate signed by the trusted CA, presented as the client's own
#   no-digital-signature clientAuth leaf whose key usage is keyEncipherment only
#   server-auth          leaf whose extended key usage is serverAuth only
#   intermediate         CA:TRUE signed by the trusted CA; via-intermediate is a clientAuth leaf it signs, and
#                        via-intermediate-chain.pem = via-intermediate + intermediate (no trust anchor)
#   bundled-signed       clientAuth leaf signed by MockServer's bundled CA key; bundled-signed-chain.pem = it + the
#                        trusted CA
#   no-eku-with-ca-chain.pem = ../no-eku-cert.pem + the trusted CA
#   bundled-reissued     a self-signed CA certificate for the bundled CA's key under another subject (recognised by
#                        key material); trusted-and-bundled-reissued.pem = the trusted CA + it
# Keys are unencrypted PKCS#8 PEM. Needs openssl 3.4+ and the upstream submodule (the bundled CA key ships in its jar).
set -eu
cd "$(dirname "$0")"
bundled=../../../../../upstream/mockserver/mockserver/mockserver-core/src/main/resources/org/mockserver/socket
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1-key.pem" 2>/dev/null; }

issue() { # name subject serial ca-cert ca-key extensions
  key "$1"
  printf '%b' "$6" > "$work/$1.ext"
  openssl req -new -key "$1-key.pem" -subj "$2" -out "$work/$1.csr"
  openssl x509 -req -in "$work/$1.csr" -CA "$4" -CAkey "$5" -set_serial "$3" -not_before 20261003000000Z \
    -not_after 21260910000000Z -extfile "$work/$1.ext" -out "$1-cert.pem" 2>/dev/null
}

self() { # name subject serial key extensions
  printf '%b' "$5" > "$work/$1.ext"
  openssl req -new -key "$4" -subj "$2" -out "$work/$1.csr"
  openssl x509 -req -in "$work/$1.csr" -key "$4" -set_serial "$3" -not_before 20261003000000Z \
    -not_after 21260910000000Z -extfile "$work/$1.ext" -out "$1-cert.pem" 2>/dev/null
}

ca='basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=none\n'
client='basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n'

key attacker-ca
self attacker-ca "/O=Fixture/CN=Attacker CA" 0x2101 attacker-ca-key.pem "$ca"
issue attacker "/O=Fixture/CN=attacker.example" 0x2102 attacker-ca-cert.pem attacker-ca-key.pem "$client"
cat attacker-cert.pem ../ca-cert.pem > attacker-chain.pem

key self-signed
self self-signed "/O=Fixture/CN=self-signed.example" 0x2103 self-signed-key.pem "$client"
cat self-signed-cert.pem ../ca-cert.pem > self-signed-chain.pem

issue ca-leaf "/O=Fixture/CN=ca-leaf.example" 0x2104 ../ca-cert.pem ../ca-key.pem "$ca"
issue no-digital-signature "/O=Fixture/CN=no-digital-signature.example" 0x2105 ../ca-cert.pem ../ca-key.pem \
  "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n"
issue server-auth "/O=Fixture/CN=server-auth.example" 0x2106 ../ca-cert.pem ../ca-key.pem \
  "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n"

issue intermediate "/O=Fixture/CN=Private Intermediate CA" 0x2107 ../ca-cert.pem ../ca-key.pem "$ca"
issue via-intermediate "/O=Fixture/CN=via-intermediate.example" 0x2108 intermediate-cert.pem intermediate-key.pem "$client"
cat via-intermediate-cert.pem intermediate-cert.pem > via-intermediate-chain.pem

issue bundled-signed "/O=Fixture/CN=bundled-signed.example" 0x2109 "$bundled/CertificateAuthorityCertificate.pem" \
  "$bundled/PKCS8CertificateAuthorityPrivateKey.pem" "$client"
cat bundled-signed-cert.pem ../ca-cert.pem > bundled-signed-chain.pem

self bundled-reissued "/O=Fixture/CN=Reissued Bundled CA" 0x210A "$bundled/PKCS8CertificateAuthorityPrivateKey.pem" "$ca"
cat ../ca-cert.pem bundled-reissued-cert.pem > trusted-and-bundled-reissued.pem

# a trusted leaf with its CA appended still authenticates
cat ../no-eku-cert.pem ../ca-cert.pem > no-eku-with-ca-chain.pem
