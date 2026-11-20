#!/bin/sh
# client key stores holding several private keys, for asyncapi_mqtt_ssl_key_choice and
# asyncapi_kafka_ssl_key_choice. Each leaf is issued by the private test CA in tests/files/tls/private-ca (the
# scenarios' tlsMutualAuthenticationCertificateChain, so the CA their server names in its CertificateRequest and
# trusts; they are off MockServer's bundled CA, which 9.1.0 never trusts for mTLS) unless named otherwise:
#   other    RSA, clientAuth, issued by "CN=Other CA" (not an issuer the server accepts)
#   good     RSA, clientAuth
#   expired  RSA, clientAuth, expired in 2001
#   server   RSA, extendedKeyUsage serverAuth only
#   ec       EC P-256, clientAuth
#   gone     RSA, clientAuth, expired in 2001 (an alias SunX509's HashMap puts after "good")
#   ec-stale EC P-256, clientAuth, expired in 2001 (likewise after "good")
# Store passwords are "changeit". Run from anywhere with openssl 3.4+ and a JDK keytool; it rewrites the stores.
set -eu
cd "$(dirname "$0")"
root=../../../../..
ca_cert=$root/tests/files/tls/private-ca/ca-cert.pem
ca_key=$root/tests/files/tls/private-ca/ca-key.pem
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/other-ca.key" -out "$work/other-ca.pem" -days 36500 \
  -subj "/CN=Other CA" 2>/dev/null

leaf() { # name keyalg eku issuer-cert issuer-key [not_before not_after]
  name=$1
  case $2 in
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/$name.key" 2>/dev/null ;;
    ec) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/$name.key" 2>/dev/null ;;
  esac
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\n' "$3" > "$work/$name.ext"
  openssl req -new -key "$work/$name.key" -subj "/CN=$name" -out "$work/$name.csr"
  if [ $# -gt 5 ]; then
    validity="-not_before $6 -not_after $7"
  else
    validity="-days 36500"
  fi
  # shellcheck disable=SC2086
  openssl x509 -req -in "$work/$name.csr" -CA "$4" -CAkey "$5" -set_serial "0x$(openssl rand -hex 8)" $validity \
    -extfile "$work/$name.ext" -out "$work/$name.pem" 2>/dev/null
  cat "$work/$name.pem" "$4" > "$work/$name.chain.pem"
  openssl pkcs12 -export -inkey "$work/$name.key" -in "$work/$name.chain.pem" -name "$name" -passout pass:changeit \
    -out "$work/$name.p12"
}

leaf other rsa clientAuth "$work/other-ca.pem" "$work/other-ca.key"
leaf good rsa clientAuth "$ca_cert" "$ca_key"
leaf expired rsa clientAuth "$ca_cert" "$ca_key" 20000101000000Z 20010101000000Z
leaf server rsa serverAuth "$ca_cert" "$ca_key"
leaf ec ec clientAuth "$ca_cert" "$ca_key"
leaf gone rsa clientAuth "$ca_cert" "$ca_key" 20000101000000Z 20010101000000Z
leaf ec-stale ec clientAuth "$ca_cert" "$ca_key" 20000101000000Z 20010101000000Z

store() { # file type alias...
  file=$1 type=$2
  shift 2
  rm -f "$file"
  for alias in "$@"; do
    keytool -importkeystore -noprompt -srckeystore "$work/$alias.p12" -srcstoretype PKCS12 -srcstorepass changeit \
      -destkeystore "$file" -deststoretype "$type" -deststorepass changeit -destkeypass changeit >/dev/null 2>&1
  done
}

store other-good.p12 PKCS12 other good
store other-good.jks JKS other good
store other.p12 PKCS12 other
store expired-good.p12 PKCS12 expired good
store good-expired.p12 PKCS12 good expired
store server-good.p12 PKCS12 server good
store good-server.p12 PKCS12 good server
store ec-good.p12 PKCS12 ec good
store good-gone.p12 PKCS12 good gone
store good-ec-stale.p12 PKCS12 good ec-stale
