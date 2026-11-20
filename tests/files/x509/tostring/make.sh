#!/bin/sh
# Regenerates the certificates of the `X509Certificate.toString` vectors (OpenSSL 3), then their expected text with
# OpenJDK 25: `sh make.sh <path to java 25>`. The bundled CA and ../{rsa_v1,rsa_v3,ec_v3}.der are copied in;
# ec_policies_ca.pem (its key is keys/log_ca_ec.pem: AIA, a CRL distribution point, a policy with a CPS qualifier) is
# kept as made once. The oracle runs OpenJDK 26.0.2; its layout is the same (scenario log_ca_debug_entries).
set -e
cd "$(dirname "$0")"
JAVA="${1:-java}"
T=$(mktemp -d)
cp ../../../../src/tls/CertificateAuthorityCertificate.pem bundled_ca.pem
cp ../rsa_v1.der rsa_v1.der
cp ../rsa_v3.der rsa_v3.der
cp ../ec_v3.der ec_v3.der

cat > "$T/ec.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = MockServer EC CA
O = Example
C = DE
[ca]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
for curve in P-256:sha256:ec_p256_ca P-384:sha384:ec_p384_ca P-521:sha512:ec_p521_ca; do
    name=${curve##*:}; rest=${curve%:*}; digest=${rest##*:}; c=${rest%%:*}
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:$c -nodes -keyout "$T/$name.key" -"$digest" \
        -days 3650 -set_serial 0x7f -config "$T/ec.cnf" -extensions ca -out "$name.pem" 2>/dev/null
done

cat > "$T/rsa.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
string_mask = utf8only
[dn]
DC = com
DC = example
OU = Unit + One
O = "Quote, Inc."
CN = " leading space"
emailAddress = ca@example.com
serialNumber = 42
[ext]
basicConstraints = CA:true
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, keyAgreement, encipherOnly, decipherOnly
extendedKeyUsage = serverAuth, codeSigning, 1.2.3.4.5, timeStamping, OCSPSigning
subjectAltName = DNS:example.com, IP:127.0.0.1, IP:::1, email:a@example.com, URI:https://example.com/x?y=1, dirName:dir_sect, RID:1.2.3.4
issuerAltName = DNS:issuer.example.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer:always
1.2.3.4.5.6 = ASN1:UTF8String:an unknown extension value long enough to wrap
[dir_sect]
CN = dir name
O = Dir Org
EOF
openssl req -x509 -newkey rsa:1024 -nodes -keyout "$T/rsa.key" -sha384 -days 365 -set_serial 0x80aabbccdd \
    -config "$T/rsa.cnf" -extensions ext -out rsa_many_extensions.pem 2>/dev/null

cat > "$T/plain.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = Plain CA
[ca]
basicConstraints = critical, CA:true, pathlen:3
EOF
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/plain.key" -sha256 -days 30 -set_serial 1 \
    -config "$T/plain.cnf" -extensions ca -out rsa_pathlen.pem 2>/dev/null

# The remaining OIDMap extension classes, signed with keys/rsa_2048_pkcs1.pem so that the CA serves as
# the configured CA of scenario log_ca_form_extensions: OpenSSL's own syntax where it has one, else ASN1 generator
# sections (IMP:n is an implicit context tag), including the CRL-only classes a certificate can still carry.
cat > "$T/ext.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = MockServer Extensions CA
O = Example
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
nameConstraints = critical, permitted;DNS:example.com, permitted;IP:192.168.0.0/255.255.0.0, permitted;IP:fd00:0:0:0:0:0:0:0/ffff:ff00:0:0:0:0:0:0, permitted;email:.example.com, permitted;URI:.example.com, permitted;dirName:dir_sect, excluded;DNS:bad.example.com, excluded;IP:10.0.0.0/255.0.0.0
policyMappings = 1.2.3.4:1.2.3.5, 1.3.6.1.4.1.99.1:1.3.6.1.4.1.99.2
policyConstraints = requireExplicitPolicy:2, inhibitPolicyMapping:0
inhibitAnyPolicy = critical, 3
nsCertType = client, server, email, objsign, sslCA, emailCA, objCA
noCheck = ignored
2.5.29.16 = ASN1:SEQUENCE:pkup
2.5.29.20 = ASN1:INTEGER:0x1234567890ABCDEF1234567890ABCDEF
2.5.29.27 = ASN1:INTEGER:7
2.5.29.21 = ASN1:ENUMERATED:1
2.5.29.29 = ASN1:SEQUENCE:issuer
2.5.29.28 = ASN1:SEQUENCE:idp
[dir_sect]
O = Permitted Org
[pkup]
notBefore = IMP:0,GENTIME:20260101000000Z
notAfter = IMP:1,GENTIME:20361231235959Z
[issuer]
dns = IMP:2,IA5STRING:issuer.example.com
uri = IMP:6,IA5STRING:http://issuer.example.com/
[idp]
point = IMP:0,SEQUENCE:idp_name
users = IMP:1,BOOLEAN:TRUE
reasons = IMP:3,FORMAT:BITLIST,BITSTRING:0,1,3,8
indirect = IMP:4,BOOLEAN:TRUE
[idp_name]
full = IMP:0,SEQUENCE:idp_names
[idp_names]
uri = IMP:6,IA5STRING:http://crl.example.com/ca.crl
CNF
openssl req -x509 -key keys/rsa_2048_pkcs1.pem -sha256 -days 3650 -set_serial 0x0674 -config "$T/ext.cnf" \
    -extensions ca -out rsa_extensions_ca.pem 2>/dev/null

# The other branches: excluded subtrees only, with minimum and maximum; inhibitPolicyMapping only; skipCerts -1;
# a notAfter-only PrivateKeyUsage; the reserved NetscapeCertType bit and Object Signing CA; an unknown reason code;
# a relative-name IssuingDistributionPoint; a critical OCSPNoCheck.
cat > "$T/ext2.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = Extension Branches
[ext]
2.5.29.30 = ASN1:SEQUENCE:nc
2.5.29.36 = ASN1:SEQUENCE:pc
2.5.29.54 = critical, ASN1:INTEGER:-1
2.5.29.16 = ASN1:SEQUENCE:pkup
2.16.840.1.113730.1.1 = ASN1:FORMAT:BITLIST,BITSTRING:4,7
2.5.29.21 = ASN1:ENUMERATED:42
2.5.29.28 = ASN1:SEQUENCE:idp
1.3.6.1.5.5.7.48.1.5 = critical, ASN1:NULL
2.5.29.33 = ASN1:SEQUENCE:maps
[nc]
excluded = IMP:1,SEQUENCE:excluded
[excluded]
a = SEQUENCE:subtree_a
b = SEQUENCE:subtree_b
[subtree_a]
name = IMP:2,IA5STRING:bad.example.com
min = IMP:0,INTEGER:1
max = IMP:1,INTEGER:5
[subtree_b]
name = IMP:1,IA5STRING:example.org
[pc]
inhibit = IMP:1,INTEGER:1
[pkup]
notAfter = IMP:1,GENTIME:20300615120000Z
[idp]
point = IMP:0,SEQUENCE:idp_name
cas = IMP:2,BOOLEAN:TRUE
attributes = IMP:5,BOOLEAN:TRUE
[idp_name]
relative = IMP:1,SET:rdn
[rdn]
cn = SEQUENCE:cn
[cn]
type = OID:commonName
value = UTF8String:CRL Partition 1
[maps]
m = SEQUENCE:map
[map]
issuer = OID:1.2.3.4
subject = OID:1.2.3.6
CNF
openssl req -x509 -newkey rsa:1024 -nodes -keyout "$T/ext2.key" -sha256 -days 30 -set_serial 2 \
    -config "$T/ext2.cnf" -extensions ext -out rsa_extension_branches.pem 2>/dev/null

# Extensions their Sun class rejects: a non-critical one is left out of `Certificate Extensions` and
# listed under `Unparseable certificate extensions` with the exception; a critical one fails the certificate, for
# which ToStringGen writes `<name>.err` instead of `<name>.txt`. One malformed value per class and failure family;
# rsa_ber_and_edi_names holds accepted values the printer must read: EDIPartyNames and an indefinite-length AIA.
cat > "$T/unparseable.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = Unparseable Extensions
[classes]
2.5.29.54 = DER:020103
2.5.29.30 = DER:3003820161
2.5.29.36 = DER:3003820100
2.5.29.33 = DER:3003020101
2.5.29.16 = DER:3003820100
2.16.840.1.113730.1.1 = DER:040100
2.5.29.19 = DER:020100
2.5.29.15 = DER:03020800
2.5.29.14 = DER:020101
2.5.29.35 = DER:3003830100
2.5.29.17 = DER:3000
2.5.29.18 = DER:30058603616263
2.5.29.37 = DER:3003020101
2.5.29.32 = DER:30020500
2.5.29.31 = DER:30023000
2.5.29.46 = DER:020100
1.3.6.1.5.5.7.1.1 = DER:300430020500
1.3.6.1.5.5.7.1.11 = DER:3008300606012a870100
2.5.29.20 = DER:0400
2.5.29.27 = DER:0200
2.5.29.21 = DER:0a050100000000
2.5.29.29 = DER:3100
2.5.29.28 = DER:3003860100
1.3.6.1.5.5.7.48.1.5 = DER:020100
1.2.3.4 = DER:0500
[der]
2.5.29.19 = DER:30050101ff
2.5.29.14 = DER:04010000
2.5.29.30 = DER:30
2.16.840.1.113730.1.1 = DER:03850000000001
2.5.29.37 = DER:308006012a0000
2.5.29.15 = DER:1f0100
2.5.29.17 = DER:30028100
2.5.29.18 = DER:30098607683a2f2f612062
2.5.29.36 = DER:300780050100000000
2.5.29.16 = DER:30058003313233
2.5.29.32 = DER:3007300506012a3000
2.5.29.31 = DER:300a30088102078081020780
2.5.29.35 = DER:3006800101800102
2.5.29.28 = DER:300481020000
2.5.29.21 = DER:020101
2.5.29.20 = DER:02020001
2.5.29.33 = DER:3005300306012a
[printed]
2.5.29.17 = DER:3010a50e80050c0361626381050c0378797a
2.5.29.18 = DER:3009a50781050c0378797a
1.3.6.1.5.5.7.1.1 = DER:3080308006082b0601050507300286036a3a2f00000000
[critical]
2.5.29.54 = critical, DER:020103
2.5.29.30 = critical, DER:3003820161
CNF
for section in classes:rsa_unparseable_extensions der:rsa_unparseable_der printed:rsa_ber_and_edi_names \
    critical:rsa_unparseable_critical; do
    openssl req -x509 -key keys/rsa_2048_pkcs1.pem -sha256 -days 30 -set_serial 0x0696 -config "$T/unparseable.cnf" \
        -extensions "${section%%:*}" -out "${section##*:}.pem" 2>/dev/null
done

rm -rf "$T"
"$JAVA" -Duser.timezone=GMT ToStringGen.java .
