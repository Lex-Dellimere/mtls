#!/bin/sh
# Regenerates the TLS test keys and certificates (Ed25519). Run from this
# directory. The CA signs a server and a client certificate.
set -e
openssl genpkey -algorithm ed25519 -out ca.key
openssl req -x509 -new -key ca.key -subj "/CN=mtls test CA" -days 36500 \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign" -out ca.pem
for who in server client; do
  openssl genpkey -algorithm ed25519 -out $who.key
  openssl req -new -key $who.key -subj "/CN=$who.test" -out $who.csr
  if [ $who = server ]; then eku=serverAuth; else eku=clientAuth; fi
  printf "subjectAltName=DNS:$who.test,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=$eku\nbasicConstraints=CA:false\n" > $who.ext
  openssl x509 -req -in $who.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 36500 -extfile $who.ext -out $who.pem
  openssl x509 -in $who.pem -outform DER -out $who.der
  openssl pkey -in $who.key -outform DER -out $who.key.der
  rm $who.csr $who.ext
done
openssl x509 -in ca.pem -outform DER -out ca.der
rm -f ca.srl
