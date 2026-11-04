#!/bin/sh
# Regenerates every fixture in this directory (the files are checked in; run
# this only to change them, then touch tests/x509*_test.mettle because the
# tests embed these files with import_str and mbuild may cache the old bytes).
#
# Needs openssl 3.4 or newer (x509 -not_before/-not_after) and python3.
# All dates are fixed, so the tests use a fixed "now" and never expire:
#   good    2025-01-01 .. 2045-01-01
#   expired 2020-01-01 .. 2021-01-01
#   future  2040-01-01 .. 2045-01-01
set -e
cd "$(dirname "$0")"

# Start clean (only the files this script makes).
for f in *.pem *.key *.der *.csr *.ext; do
  if [ -e "$f" ]; then rm -f "$f"; fi
done

GOOD_FROM=20250101000000Z
GOOD_TO=20450101000000Z
SERIAL=100

sign() { # out csr ca ext from to [extra openssl args]
  out=$1; csr=$2; ca=$3; ext=$4; from=$5; to=$6
  shift 6
  SERIAL=$((SERIAL + 1))
  openssl x509 -req -in "$csr" -CA "$ca.pem" -CAkey "$ca.key" -set_serial $SERIAL \
    -not_before "$from" -not_after "$to" -extfile "$ext" "$@" -out "$out.pem" 2>/dev/null
}

selfsign() { # out ext [extra]
  out=$1; ext=$2
  shift 2
  SERIAL=$((SERIAL + 1))
  openssl x509 -req -in "$out.csr" -signkey "$out.key" -set_serial $SERIAL \
    -not_before $GOOD_FROM -not_after $GOOD_TO -extfile "$ext" "$@" -out "$out.pem" 2>/dev/null
}

csr() { # name subject
  openssl req -new -key "$1.key" -subj "$2" -out "$1.csr" 2>/dev/null
}

edkey() { openssl genpkey -algorithm ed25519 -out "$1.key"; }

# ---- extension profiles ------------------------------------------------
ca_ext() { # file [pathlen] [extra lines...]
  f=$1; pl=""
  if [ -n "$2" ]; then pl=",pathlen:$2"; fi
  shift 2
  {
    echo "basicConstraints=critical,CA:TRUE$pl"
    echo "keyUsage=critical,keyCertSign,cRLSign"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid"
    for l in "$@"; do echo "$l"; done
  } > "$f"
}

leaf_ext() { # file san [extra lines...]
  f=$1; san=$2
  shift 2
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid"
    echo "subjectAltName=$san"
    for l in "$@"; do echo "$l"; done
  } > "$f"
}

SAN="DNS:example.test,DNS:*.wild.test,DNS:Mixed.Case.Test,IP:192.0.2.1,IP:2001:db8::1"

# ---- the Ed25519 PKI ---------------------------------------------------
edkey root;  csr root  "/O=mtls test/CN=mtls Test Root"
edkey inter; csr inter "/O=mtls test/CN=mtls Test Intermediate"
edkey leaf;  csr leaf  "/O=mtls test/CN=example.test"

ca_ext r.ext ""
selfsign root r.ext
ca_ext i.ext 0
sign inter inter.csr root i.ext $GOOD_FROM $GOOD_TO

leaf_ext l.ext "$SAN" "extendedKeyUsage=serverAuth,clientAuth"
sign leaf leaf.csr inter l.ext $GOOD_FROM $GOOD_TO

# Dates and key usage variants of the leaf (same key, signed by inter).
sign leaf_expired leaf.csr inter l.ext 20200101000000Z 20210101000000Z
sign leaf_future  leaf.csr inter l.ext 20400101000000Z $GOOD_TO
leaf_ext l2.ext "$SAN" "extendedKeyUsage=clientAuth"
sign leaf_clientonly leaf.csr inter l2.ext $GOOD_FROM $GOOD_TO
leaf_ext l3.ext "$SAN" "extendedKeyUsage=anyExtendedKeyUsage"
sign leaf_anyeku leaf.csr inter l3.ext $GOOD_FROM $GOOD_TO
leaf_ext l4.ext "$SAN"
sign leaf_noeku leaf.csr inter l4.ext $GOOD_FROM $GOOD_TO
leaf_ext l5.ext "$SAN" "1.2.3.4.5=critical,DER:0500"
sign leaf_critext leaf.csr inter l5.ext $GOOD_FROM $GOOD_TO
leaf_ext l6.ext "$SAN" "1.2.3.4.6=DER:0500"
sign leaf_noncritext leaf.csr inter l6.ext $GOOD_FROM $GOOD_TO

# A root that did not sign inter: its leaf must not verify.
edkey root2; csr root2 "/O=mtls test/CN=mtls Other Root"
selfsign root2 r.ext
sign leaf_otherroot leaf.csr root2 l4.ext $GOOD_FROM $GOOD_TO

# Intermediate that is not a CA.
edkey notca; csr notca "/O=mtls test/CN=mtls Not A CA"
{ echo "basicConstraints=critical,CA:FALSE"; echo "keyUsage=critical,digitalSignature"; echo "subjectKeyIdentifier=hash"; echo "authorityKeyIdentifier=keyid"; } > n.ext
sign notca notca.csr root n.ext $GOOD_FROM $GOOD_TO
sign leaf_under_notca leaf.csr notca l4.ext $GOOD_FROM $GOOD_TO

# CA whose key usage lacks keyCertSign.
edkey noks; csr noks "/O=mtls test/CN=mtls No KeyCertSign"
{ echo "basicConstraints=critical,CA:TRUE"; echo "keyUsage=critical,digitalSignature"; echo "subjectKeyIdentifier=hash"; echo "authorityKeyIdentifier=keyid"; } > k.ext
sign noks noks.csr root k.ext $GOOD_FROM $GOOD_TO
sign leaf_under_noks leaf.csr noks l4.ext $GOOD_FROM $GOOD_TO

# CA limited to client auth.
edkey clientca; csr clientca "/O=mtls test/CN=mtls Client Only CA"
ca_ext c.ext 0 "extendedKeyUsage=clientAuth"
sign clientca clientca.csr root c.ext $GOOD_FROM $GOOD_TO
sign leaf_under_clientca leaf.csr clientca l4.ext $GOOD_FROM $GOOD_TO

# Path length: inter (pathlen 0) -> inter2 -> leaf is too deep.
edkey inter2; csr inter2 "/O=mtls test/CN=mtls Intermediate Two"
ca_ext i2.ext ""
sign inter2 inter2.csr inter i2.ext $GOOD_FROM $GOOD_TO
sign leaf_under_inter2 leaf.csr inter2 l4.ext $GOOD_FROM $GOOD_TO

# A deeper chain that is allowed: root -> p1 (pathlen 1) -> p0 (pathlen 0) -> leaf.
edkey p1; csr p1 "/O=mtls test/CN=mtls Path One"
ca_ext p1.ext 1
sign p1 p1.csr root p1.ext $GOOD_FROM $GOOD_TO
edkey p0; csr p0 "/O=mtls test/CN=mtls Path Zero"
ca_ext p0.ext 0
sign p0 p0.csr p1 p0.ext $GOOD_FROM $GOOD_TO
sign leaf_deep leaf.csr p0 l.ext $GOOD_FROM $GOOD_TO

# Name constraints.
edkey ncca; csr ncca "/O=mtls test/CN=mtls Name Constrained CA"
ca_ext nc.ext 0 "nameConstraints=critical,permitted;DNS:permitted.test,excluded;DNS:bad.permitted.test"
sign ncca ncca.csr root nc.ext $GOOD_FROM $GOOD_TO
leaf_ext a.ext "DNS:a.permitted.test,DNS:permitted.test"
sign leaf_nc_ok leaf.csr ncca a.ext $GOOD_FROM $GOOD_TO
leaf_ext b.ext "DNS:other.test"
sign leaf_nc_out leaf.csr ncca b.ext $GOOD_FROM $GOOD_TO
leaf_ext c2.ext "DNS:x.bad.permitted.test"
sign leaf_nc_excl leaf.csr ncca c2.ext $GOOD_FROM $GOOD_TO
leaf_ext d.ext "DNS:*.permitted.test"
sign leaf_nc_wild leaf.csr ncca d.ext $GOOD_FROM $GOOD_TO
leaf_ext d2.ext "DNS:*.test"
sign leaf_nc_widewild leaf.csr ncca d2.ext $GOOD_FROM $GOOD_TO
# A constraint of a kind we do not evaluate, marked critical.
edkey ncmail; csr ncmail "/O=mtls test/CN=mtls Email Constrained CA"
ca_ext nm.ext 0 "nameConstraints=critical,permitted;email:example.test"
sign ncmail ncmail.csr root nm.ext $GOOD_FROM $GOOD_TO
sign leaf_under_ncmail leaf.csr ncmail l4.ext $GOOD_FROM $GOOD_TO

# Expired issuers: same name and key as the good ones, old dates.
sign inter_old inter.csr root i.ext 20200101000000Z 20210101000000Z
SERIAL=$((SERIAL + 1))
openssl x509 -req -in root.csr -signkey root.key -set_serial $SERIAL \
  -not_before 20200101000000Z -not_after 20210101000000Z -extfile r.ext -out root_old.pem 2>/dev/null

# A second "intermediate" with the same name, the same key identifier but
# another key, so the path builder has to try it and back out.
edkey evil; csr evil "/O=mtls test/CN=mtls Test Intermediate"
SKI=$(openssl x509 -in inter.pem -noout -ext subjectKeyIdentifier | tail -n 1 | tr -d ' ')
{ echo "basicConstraints=critical,CA:TRUE"; echo "keyUsage=critical,keyCertSign,cRLSign"; echo "subjectKeyIdentifier=$SKI"; } > e.ext
sign inter_evil evil.csr root e.ext $GOOD_FROM $GOOD_TO

# Two CAs that certify each other, to make sure the search ends.
edkey loopx; csr loopx "/O=mtls test/CN=mtls Loop X"
edkey loopy; csr loopy "/O=mtls test/CN=mtls Loop Y"
ca_ext lp.ext ""
selfsign loopy lp.ext
sign loopx loopx.csr loopy lp.ext $GOOD_FROM $GOOD_TO
sign loopy1 loopy.csr loopx lp.ext $GOOD_FROM $GOOD_TO
sign leaf_loop leaf.csr loopx l4.ext $GOOD_FROM $GOOD_TO

# A self-signed end-entity certificate (trusted by being in the store).
edkey selfleaf; csr selfleaf "/O=mtls test/CN=self.test"
leaf_ext s.ext "DNS:self.test"
selfsign selfleaf s.ext

# ---- crafted variants (v1 root, duplicate extension, junk) ---------------
python3 craft.py

# ---- ECDSA ----------------------------------------------------------------
for c in 256:prime256v1:sha256 384:secp384r1:sha384; do
  bits=${c%%:*}; rest=${c#*:}; curve=${rest%%:*}; md=${rest#*:}
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve -pkeyopt ec_param_enc:named_curve -out ec${bits}_root.key
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve -pkeyopt ec_param_enc:named_curve -out ec${bits}_leaf.key
  csr ec${bits}_root "/O=mtls test/CN=mtls EC$bits Root"
  csr ec${bits}_leaf "/O=mtls test/CN=example.test"
  selfsign ec${bits}_root r.ext -$md
  sign ec${bits}_leaf ec${bits}_leaf.csr ec${bits}_root l.ext $GOOD_FROM $GOOD_TO -$md
  openssl ec -in ec${bits}_leaf.key -out ec${bits}_leaf_sec1.key 2>/dev/null
  openssl pkey -in ec${bits}_leaf.key -outform DER -out ec${bits}_leaf_p8.der
done

# ---- RSA --------------------------------------------------------------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_root.key 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_leaf.key 2>/dev/null
csr rsa_root "/O=mtls test/CN=mtls RSA Root"
csr rsa_leaf "/O=mtls test/CN=example.test"
selfsign rsa_root r.ext -sha256
sign rsa_leaf rsa_leaf.csr rsa_root l.ext $GOOD_FROM $GOOD_TO -sha256
sign rsa_leaf_sha384 rsa_leaf.csr rsa_root l.ext $GOOD_FROM $GOOD_TO -sha384
sign rsa_leaf_sha512 rsa_leaf.csr rsa_root l.ext $GOOD_FROM $GOOD_TO -sha512
sign rsa_leaf_pss rsa_leaf.csr rsa_root l.ext $GOOD_FROM $GOOD_TO -sha256 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256
sign rsa_leaf_pss20 rsa_leaf.csr rsa_root l.ext $GOOD_FROM $GOOD_TO -sha256 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 -sigopt rsa_mgf1_md:sha256
openssl rsa -in rsa_leaf.key -traditional -out rsa_leaf_pkcs1.key 2>/dev/null
openssl pkey -in rsa_leaf.key -outform DER -out rsa_leaf_p8.der
openssl rsa -in rsa_leaf.key -traditional -outform DER -out rsa_leaf_pkcs1.der 2>/dev/null

# A weak (1024 bit) CA: parses, but the verifier refuses it.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa1024_root.key 2>/dev/null
csr rsa1024_root "/O=mtls test/CN=mtls RSA1024 Root"
selfsign rsa1024_root r.ext -sha256
sign rsa1024_leaf rsa_leaf.csr rsa1024_root l.ext $GOOD_FROM $GOOD_TO -sha256

# ---- keys in other shapes ---------------------------------------------------
openssl pkey -in leaf.key -outform DER -out leaf_p8.der
openssl pkcs8 -topk8 -in leaf.key -v2 aes-256-cbc -passout pass:mtls -out leaf_encrypted.key 2>/dev/null
cat leaf.pem leaf.key > leaf_bundle.pem

# Scratch files that are not fixtures.
rm -f ./*.csr ./*.ext

# fixtures.mettle: every file above as a string constant, for the tests.
{
  echo "// Generated by make.sh: the fixture files as strings (leaf.pem becomes MTLS_T_LEAF_PEM)."
  echo
  echo 'import "std/mem";'
  echo 'import "mtls/core/err";'
  echo 'import "mtls/x509/pem";'
  echo
  for f in *.pem *.key *.der; do
    n=$(echo "$f" | tr 'a-z.' 'A-Z_')
    echo "export const MTLS_T_$n: string = import_str \"$f\";"
  done
  count=0
  for f in *.pem *.key *.der; do count=$((count + 1)); done
  echo
  echo "/// mtls_t_count / mtls_t_get / mtls_t_label: every fixture by number."
  echo "export fn mtls_t_count() -> int32 { return $count; }"
  echo
  echo "export fn mtls_t_get(i: int32) -> string {"
  echo "  switch (i) {"
  i=0
  for f in *.pem *.key *.der; do
    n=$(echo "$f" | tr 'a-z.' 'A-Z_')
    echo "    case $i: { return MTLS_T_$n; }"
    i=$((i + 1))
  done
  echo "    default: { }"
  echo "  }"
  echo '  return "";'
  echo "}"
  echo
  echo "export fn mtls_t_label(i: int32) -> string {"
  echo "  switch (i) {"
  i=0
  for f in *.pem *.key *.der; do
    echo "    case $i: { return \"$f\"; }"
    i=$((i + 1))
  done
  echo "    default: { }"
  echo "  }"
  echo '  return "";'
  echo "}"
  cat <<'EOT'

/// mtls_t_pem_der: the DER of the first PEM block in text, into out (cap
/// bytes). Returns its length, or -1.
export fn mtls_t_pem_der(text: string, out: uint8*, cap: int64) -> int64 {
  var it: MtlsPemIter;
  var blk: MtlsPemBlock;
  var n: int64 = 0;
  mtls_pem_iter(&it, text.chars, (int64)text.length);
  if (mtls_pem_next(&it, &blk) != 1) { return -1; }
  if (mtls_pem_decode(&blk, out, cap, &n) != MTLS_OK) { return -1; }
  return n;
}
EOT
} > fixtures.mettle
