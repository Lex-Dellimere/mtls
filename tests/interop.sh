#!/bin/sh
# Interop with OpenSSL: mtls-client against `openssl s_server` and
# `openssl s_client` against mtls-server, both TLS versions, several
# suites, mutual TLS, resumption and HelloRetryRequest.
#
# Usage: sh tests/interop.sh BINDIR   (run from the project root;
# `mbuild interop` builds the release tools and runs this).
BIN=${1:-build/linux/release}
D=tests/data/tls
T=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
PORT=$((20000 + $$ % 20000))
pass=0
fail=0

check() {   # check NAME FILE PATTERN
  if grep -q -- "$3" "$2"; then
    pass=$((pass + 1)); echo "ok    $1"
  else
    fail=$((fail + 1)); echo "FAIL  $1"; sed 's/^/      /' "$2" | head -20
  fi
}

next_port() { PORT=$((PORT + 1)); }

# mtls-client -> openssl s_server
ossl_server() {   # NAME PATTERN "s_server args" "mtls-client args"
  next_port
  openssl s_server -accept $PORT -www -naccept 4 $3 >"$T/srv.log" 2>&1 &
  sleep 0.4
  timeout 20 "$BIN/mtls-client" $4 --servername server.test --get / 127.0.0.1 $PORT >"$T/out" 2>&1
  check "$1" "$T/out" "$2"
  kill $! 2>/dev/null; wait $! 2>/dev/null
}

ED="-cert $D/server.pem -key $D/server.key"
EC="-cert $D/ecserver.pem -key $D/ecserver.key -cert_chain $D/ecinter.pem"
ossl_server "client 1.3 AES-128-GCM"       "TLS 1.3, TLS_AES_128_GCM_SHA256.*verified yes" "$EC -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256" "--ca $D/ecroot.pem"
ossl_server "client 1.3 AES-256-GCM"       "TLS_AES_256_GCM_SHA384" "$EC -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384" "--ca $D/ecroot.pem"
ossl_server "client 1.3 ChaCha20"          "TLS_CHACHA20_POLY1305_SHA256" "$EC -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256" "--ca $D/ecroot.pem"
ossl_server "client 1.3 Ed25519 cert"      "verified yes" "$ED -tls1_3" "--ca $D/ca.pem"
ossl_server "client 1.3 HelloRetryRequest" "TLS 1.3.*verified yes" "$EC -tls1_3 -groups P-256" "--ca $D/ecroot.pem"
ossl_server "client 1.3 P-256 share"       "TLS 1.3" "$EC -tls1_3 -groups P-256" "--ca $D/ecroot.pem --groups p256"
ossl_server "client 1.3 ALPN"              "alpn 'h2'" "$EC -tls1_3 -alpn h2" "--ca $D/ecroot.pem --alpn h2"
ossl_server "client 1.3 resumption"        "resumed yes" "$EC -tls1_3" "--ca $D/ecroot.pem --resume 1"
ossl_server "client 1.3 client cert"       "200 ok" "$EC -tls1_3 -Verify 1 -CAfile $D/ca.pem -verify_return_error" "--ca $D/ecroot.pem --cert $D/client.pem --key $D/client.key"
ossl_server "client 1.2 ECDHE-ECDSA-AES128" "TLS 1.2, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.*verified yes" "$EC -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256" "--ca $D/ecroot.pem"
ossl_server "client 1.2 ECDHE-ECDSA-AES256" "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" "$EC -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384" "--ca $D/ecroot.pem"
ossl_server "client 1.2 ECDHE-ECDSA-CHACHA" "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" "$EC -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305" "--ca $D/ecroot.pem"
ossl_server "client 1.2 Ed25519 cert"      "TLS 1.2.*verified yes" "$ED -tls1_2" "--ca $D/ca.pem"
ossl_server "client 1.2 resumption"        "resumed yes" "$EC -tls1_2" "--ca $D/ecroot.pem --resume 1"
ossl_server "client 1.2 client cert"       "200 ok" "$EC -tls1_2 -Verify 1 -CAfile $D/ca.pem -verify_return_error" "--ca $D/ecroot.pem --cert $D/client.pem --key $D/client.key"
ossl_server "client refuses wrong CA"      "certificate: unknown issuer" "$EC -tls1_3" "--ca $D/ca.pem"

# openssl s_client -> mtls-server
mtls_server() {   # NAME PATTERN "mtls-server args" "s_client args" [runs]
  next_port
  n=${5:-1}
  "$BIN/mtls-server" --port $PORT --count $n $3 >"$T/srv.log" 2>&1 &
  sleep 0.4
  i=0
  while [ $i -lt $n ]; do
    echo "hello mtls" | timeout 10 openssl s_client -connect 127.0.0.1:$PORT -servername server.test \
      -verify_return_error -ign_eof $4 >"$T/out.$i" 2>&1
    i=$((i + 1))
  done
  wait $! 2>/dev/null
  cat "$T"/out.* "$T/srv.log" >"$T/out"
  rm -f "$T"/out.*
  check "$1" "$T/out" "$2"
}

SED="--cert $D/server.pem --key $D/server.key"
SEC="--cert $D/ecserver-chain.pem --key $D/ecserver.key"
mtls_server "server 1.3 AES-128-GCM"   "Cipher is TLS_AES_128_GCM_SHA256" "$SEC" "-CAfile $D/ecroot.pem -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256"
mtls_server "server 1.3 AES-256-GCM"   "Cipher is TLS_AES_256_GCM_SHA384" "$SEC" "-CAfile $D/ecroot.pem -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384"
mtls_server "server 1.3 ChaCha20"      "Cipher is TLS_CHACHA20_POLY1305_SHA256" "$SEC" "-CAfile $D/ecroot.pem -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256"
mtls_server "server 1.3 Ed25519 cert"  "Verify return code: 0" "$SED" "-CAfile $D/ca.pem -tls1_3"
mtls_server "server 1.3 echo"          "^hello mtls" "$SEC" "-CAfile $D/ecroot.pem -tls1_3"
mtls_server "server 1.3 HelloRetryRequest" "Cipher is TLS_AES" "$SEC --groups p256" "-CAfile $D/ecroot.pem -tls1_3 -groups X25519:P-256"
mtls_server "server 1.3 ALPN"          "ALPN protocol: http/1.1" "$SEC --alpn h2 --alpn http/1.1" "-CAfile $D/ecroot.pem -alpn http/1.1"
mtls_server "server 1.3 client cert"   "client cert yes" "$SEC --ca $D/ca.pem --require-client" "-CAfile $D/ecroot.pem -cert $D/client.pem -key $D/client.key"
mtls_server "server 1.3 needs cert"    "handshake failed" "$SEC --ca $D/ca.pem --require-client" "-CAfile $D/ecroot.pem"
mtls_server "server 1.2 ECDHE-ECDSA-AES128" "Cipher is ECDHE-ECDSA-AES128-GCM-SHA256" "$SEC" "-CAfile $D/ecroot.pem -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256"
mtls_server "server 1.2 ECDHE-ECDSA-AES256" "Cipher is ECDHE-ECDSA-AES256-GCM-SHA384" "$SEC" "-CAfile $D/ecroot.pem -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384"
mtls_server "server 1.2 ECDHE-ECDSA-CHACHA" "Cipher is ECDHE-ECDSA-CHACHA20-POLY1305" "$SEC" "-CAfile $D/ecroot.pem -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305"
mtls_server "server 1.2 Ed25519 cert"  "Verify return code: 0" "$SED" "-CAfile $D/ca.pem -tls1_2"
mtls_server "server 1.2 client cert"   "client cert yes" "$SEC --ca $D/ca.pem --require-client" "-CAfile $D/ecroot.pem -tls1_2 -cert $D/client.pem -key $D/client.key"

# Resumption needs two connections and a saved session.
for v in tls1_3 tls1_2; do
  next_port
  "$BIN/mtls-server" --port $PORT --count 2 $SEC >"$T/srv.log" 2>&1 &
  sleep 0.4
  echo a | timeout 10 openssl s_client -connect 127.0.0.1:$PORT -$v -CAfile $D/ecroot.pem -sess_out "$T/sess" -ign_eof >/dev/null 2>&1
  echo b | timeout 10 openssl s_client -connect 127.0.0.1:$PORT -$v -CAfile $D/ecroot.pem -sess_in "$T/sess" -ign_eof >"$T/out" 2>&1
  wait $! 2>/dev/null
  cat "$T/srv.log" >>"$T/out"
  check "server $v resumption" "$T/out" "resumed yes"
done

echo "interop: $pass passed, $fail failed"
[ $fail -eq 0 ]
