#!/bin/sh
# the certificates of the webhook_tls_*_log_entries scenarios, each a way a JSSE client refuses the upstream's chain
# under CUSTOM trust (the root is ca.pem, from gen.sh, which must have been run first). Run from this directory.
#   probe-san       leaf for DNS:wrong.example only (a host name mismatch)
#   probe-eku       leaf whose extendedKeyUsage is clientAuth (EndEntityChecker refuses it)
#   probe-expint    leaf signed by an intermediate CA that expired in 2016 (PKIX path validation failed)
#   probe-noca      leaf signed by an intermediate that is not a CA (basic constraints check failed)
# probe-<n>.pem is the leaf then (for expint, noca) its intermediate; probe-<n>-ca.pem and -ca-key.pem the intermediate.
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sans="DNS:localhost,IP:127.0.0.1"
for third in 0 1; do
  for fourth in $(seq 0 255); do
    sans="$sans,IP:172.17.$third.$fourth"
  done
done
leaf() { # name issuer-cert issuer-key serial extended-key-usage subject-alternative-names
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%s\nsubjectAltName=%s\n' "$5" "$6" > "$work/$1.ext"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout "probe-$1-key.pem" -out "$work/$1.csr" 2> /dev/null
  openssl x509 -req -in "$work/$1.csr" -CA "$2" -CAkey "$3" -set_serial "$4" -days 36500 -extfile "$work/$1.ext" -out "$work/$1.pem" 2> /dev/null
}
leaf san ca.pem ca-key.pem 9221 serverAuth "DNS:wrong.example"
cp "$work/san.pem" probe-san.pem
leaf eku ca.pem ca-key.pem 9222 clientAuth "$sans"
cp "$work/eku.pem" probe-eku.pem
intermediate() { # name extensions then x509 arguments
  n=$1; ext=$2; shift 2
  openssl req -newkey rsa:2048 -nodes -subj "/CN=probe $n intermediate" -keyout "probe-$n-ca-key.pem" -out "$work/i.csr" 2> /dev/null
  printf '%s\n' "$ext" > "$work/i.ext"
  openssl x509 -req -in "$work/i.csr" -CA ca.pem -CAkey ca-key.pem -set_serial 9223 -extfile "$work/i.ext" -out "probe-$n-ca.pem" "$@" 2> /dev/null
  leaf "$n" "probe-$n-ca.pem" "probe-$n-ca-key.pem" 9224 serverAuth "$sans"
  cat "$work/$n.pem" "probe-$n-ca.pem" > "probe-$n.pem"
}
intermediate expint 'basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign' -not_before 20150101000000Z -not_after 20160101000000Z
intermediate noca 'basicConstraints=CA:FALSE
keyUsage=keyCertSign' -days 36500
chmod 644 probe-*.pem
