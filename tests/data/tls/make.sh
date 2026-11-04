#!/bin/sh
# Regenerates the TLS test keys and certificates. Run from this
# directory. An Ed25519 CA signs a server and a client certificate; a P-256
# root signs an intermediate that signs a second server certificate.
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
  rm $who.csr $who.ext
done
rm -f ca.srl ca.key

# P-256: root -> intermediate -> server, so chains longer than one are tested.
openssl ecparam -name prime256v1 -genkey -noout -out ecroot.key
openssl req -x509 -new -key ecroot.key -subj "/CN=mtls test EC root" -days 36500 \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign" -out ecroot.pem
openssl ecparam -name prime256v1 -genkey -noout -out ecinter.key
openssl req -new -key ecinter.key -subj "/CN=mtls test EC intermediate" -out ecinter.csr
printf "basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign\n" > ecinter.ext
openssl x509 -req -in ecinter.csr -CA ecroot.pem -CAkey ecroot.key -CAcreateserial -days 36500 -extfile ecinter.ext -out ecinter.pem
openssl ecparam -name prime256v1 -genkey -noout -out ecserver.key
openssl req -new -key ecserver.key -subj "/CN=server.test" -out ecserver.csr
printf "subjectAltName=DNS:server.test,DNS:*.server.test\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:false\n" > ecserver.ext
openssl x509 -req -in ecserver.csr -CA ecinter.pem -CAkey ecinter.key -CAcreateserial -days 36500 -extfile ecserver.ext -out ecserver.pem
cat ecserver.pem ecinter.pem > ecserver-chain.pem
rm -f *.csr *.ext *.srl ecinter.key ecroot.key
