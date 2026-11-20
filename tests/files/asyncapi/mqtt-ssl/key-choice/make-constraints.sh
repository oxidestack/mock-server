#!/bin/sh
# client key stores for asyncapi_mqtt_ssl_key_constraints. Leaves are issued by the private test CA in
# tests/files/tls/private-ca; `md5` is signed with MD5, `rsa512` has a 512-bit RSA key, `good` is plain. Stores:
# md5-good, good-md5, rsa512-good, good-rsa512 (password "changeit"). Needs openssl 3.4+ and a JDK keytool.
set -eu
cd "$(dirname "$0")"
ca=../../../../../tests/files/tls/private-ca
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n' > "$work/ext"
leaf() { # name bits digest
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$2" -out "$work/$1.key" 2>/dev/null
  openssl req -new -key "$work/$1.key" -subj "/CN=$1" -out "$work/$1.csr"
  openssl x509 -req -in "$work/$1.csr" -CA $ca/ca-cert.pem -CAkey $ca/ca-key.pem -set_serial "0x$(openssl rand -hex 8)" \
    -days 36500 -"$3" -extfile "$work/ext" -out "$work/$1.pem" 2>/dev/null
  cat "$work/$1.pem" $ca/ca-cert.pem > "$work/$1.chain.pem"
  openssl pkcs12 -export -inkey "$work/$1.key" -in "$work/$1.chain.pem" -name "$1" -passout pass:changeit -out "$work/$1.p12"
}
leaf md5 2048 md5
leaf rsa512 512 sha256
leaf good 2048 sha256
store() { file=$1; shift; rm -f "$file"
  for a in "$@"; do keytool -importkeystore -noprompt -srckeystore "$work/$a.p12" -srcstoretype PKCS12 -srcstorepass changeit \
    -destkeystore "$file" -deststoretype PKCS12 -deststorepass changeit -destkeypass changeit >/dev/null 2>&1; done; }
store md5-good.p12 md5 good
store good-md5.p12 good md5
store rsa512-good.p12 rsa512 good
store good-rsa512.p12 good rsa512
