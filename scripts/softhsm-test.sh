#!/bin/sh
# Runs the token tests against SoftHSM, a software PKCS#11 token: once with an
# RSA key and once with an elliptic-curve key. Needs softhsm2, opensc and
# openssl (Debian/Ubuntu: apt-get install softhsm2 opensc openssl).
set -eu

module=$(find /usr/lib /usr/local/lib -name libsofthsm2.so 2>/dev/null | head -n 1)
[ -n "$module" ] || { echo "libsofthsm2.so bulunamadı" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for kind in rsa ec; do
    mkdir -p "$work/$kind/tokens"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$work/$kind/tokens" > "$work/$kind/softhsm2.conf"
    export SOFTHSM2_CONF="$work/$kind/softhsm2.conf"

    softhsm2-util --init-token --free --label sinama --pin 1234 --so-pin 5678 > /dev/null

    if [ "$kind" = rsa ]; then
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/$kind/key.pem" 2> /dev/null
    else
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/$kind/key.pem" 2> /dev/null
    fi

    # A CA certificate and an authentication certificate sit on the card too; the signing one must be picked.
    openssl req -new -x509 -key "$work/$kind/key.pem" -subj "/CN=Kok" -days 1 -addext "basicConstraints=critical,CA:TRUE" -outform DER -out "$work/$kind/ca.der" 2> /dev/null
    openssl req -new -x509 -key "$work/$kind/key.pem" -subj "/CN=Kimlik Dogrulama" -days 1 -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" -outform DER -out "$work/$kind/auth.der" 2> /dev/null
    openssl req -new -x509 -key "$work/$kind/key.pem" -subj "/CN=Nitelikli Imza" -days 1 -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,nonRepudiation" -outform DER -out "$work/$kind/sign.der" 2> /dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$work/$kind/key.pem" -outform DER -out "$work/$kind/key.der"

    tool="pkcs11-tool --module $module --login --pin 1234"
    $tool --write-object "$work/$kind/key.der" --type privkey --id 01 --label imza > /dev/null
    $tool --write-object "$work/$kind/ca.der" --type cert --id 03 --label kok > /dev/null
    $tool --write-object "$work/$kind/auth.der" --type cert --id 02 --label kimlik > /dev/null
    $tool --write-object "$work/$kind/sign.der" --type cert --id 01 --label imza > /dev/null

    echo "== $kind"
    EYAZISMA_IMZA_TEST_PKCS11="$module" EYAZISMA_IMZA_TEST_PIN=1234 EYAZISMA_IMZA_TEST_NAME="Nitelikli Imza" \
        go test ./internal/token -run TestSigningWithATokenThroughItsDriver -count=1 -v
done
