#!/bin/bash

# Build the test harness
cd example/rust-crypto
cargo update --quiet || exit 1
cargo build --profile release --quiet || exit 1
# Record exactly which crate the harness was built against
cargo tree --quiet --depth 1 | tee ~/marvin-toolkit/harness-deps.txt
cd ~/marvin-toolkit

# Parse CLI inputs to $size and $repeat
size=2048
repeat=100000
mode=pkcs1v15
keygen_only=0
lean=0

# Function to display help message
display_help() {
  echo "Usage: $0 [-s SIZE] [-n NUMBER] [-m MODE] [-g] [-l] [-h]"
  echo "  -s SIZE    Set the RSA key size (1024, 2048, or 4096; default: 2048)"
  echo "  -n NUMBER  Set the repeat number (integer; default: 100000)"
  echo "  -m MODE    Padding scheme to test (pkcs1v15 or oaep; default: pkcs1v15)"
  echo "  -g         Generate the key pair, copy it to outputs/keys and exit"
  echo "  -l         Lean: skip the per-run analysis and keep only timing.csv (for parallel-run.sh)"
  echo "  -h         Display this help message"
}

# Parse command-line arguments using getopts
while getopts ":s:n:m:glh" opt; do
  case $opt in
    s)
      size=$OPTARG
      if [[ ! "$size" =~ ^(1024|2048|4096)$ ]]; then
        echo "Error: Invalid size. Please choose 1024, 2048, or 4096."
        exit 1
      fi
      ;;
    n)
      repeat=$OPTARG
      if ! [[ "$repeat" =~ ^[0-9]+$ ]]; then
        echo "Error: Invalid number. Please specify a valid integer."
        exit 1
      fi
      ;;
    m)
      mode=$OPTARG
      if [[ ! "$mode" =~ ^(pkcs1v15|oaep)$ ]]; then
        echo "Error: Invalid mode. Please choose pkcs1v15 or oaep."
        exit 1
      fi
      ;;
    g)
      keygen_only=1
      ;;
    l)
      lean=1
      ;;
    h)
      display_help
      exit 0
      ;;
    \?)
      echo "Error: Invalid option -$OPTARG"
      display_help
      exit 1
      ;;
    :)
      echo "Error: Option -$OPTARG requires an argument."
      display_help
      exit 1
      ;;
  esac
done
size_bytes=$(($size / 8))

# Step 1: Generate key pairs, unless a key was mounted at rsa${size}/ (parallel runs share
# one key so that their timings can be merged; see parallel-run.sh)
. ./certgen/certgen/lib.sh
name="rsa${size}"
if [[ -f $name/pkcs8.pem && -f $name/cert.pem ]]; then
  echo "Using the existing key in $name/"
else
tmp_file="$(mktemp)"
if ! x509KeyGen -s $size $name &> "$tmp_file"; then
    echo "ERROR $size bit key generation failed" >&2
    cat "$tmp_file" >&2
    exit 1
fi
if ! x509SelfSign $name &> "$tmp_file"; then
    echo "ERROR: $size bit key self-signing failed" >&2
    cat "$tmp_file" >&2
    exit 1
fi
fi

echo "RSA $size bit private key in old OpenSSL PEM format is in" $(x509Key $name)
echo "RSA $size bit private key in old OpenSSL DER format is in" $(x509Key --der $name)
echo "RSA $size bit private key in PKCS#8 PEM format is in" $(x509Key --pkcs8 $name)
echo "RSA $size bit private key in PKCS#8 DER format is in" $(x509Key --der --pkcs8 $name)
echo "RSA $size bit private key in PKCS#12 format is in" $(x509Key --with-cert --pkcs12 $name)
echo "RSA $size bit self-signed certificate is in" $(x509Cert $name)
echo

# The lines above also create the PKCS#8 and DER forms of the key, so this comes after them
if [[ $keygen_only == 1 ]]; then
  cp -r $name ~/marvin-toolkit/outputs/keys
  echo "Key pair written to outputs/keys"
  exit 0
fi

# From here on, stop at the first failing step: a later step run against missing files
# would otherwise hide the real error and the container would still exit 0.
set -e

# Generate ciphertexts
if [[ "$mode" == oaep ]]; then
  # The classes the toolkit recommends for an OAEP interface (its step2-oaep-alt.sh), plus
  # two valid OAEP ciphertexts from oaep_step2.py. `too_short_payload` gives decrypted values
  # with 1, 3, 7 and 15 extra leading zero bytes. SHA-256 OAEP holds at most k - 66 bytes.
  PYTHONPATH=tlsfuzzer:. ./marvin-venv/bin/python ./oaep_step2.py \
  -c rsa${size}/cert.pem -o rsa${size}_repeat \
  --repeat ${repeat} --verbose \
  no_structure valid=0 \
  too_short_payload="0 1" too_short_payload="0 3" too_short_payload="0 7" \
  too_short_payload="0 15" \
  no_padding=48 signature_padding=8 \
  valid_repeated_byte_payload="$((size_bytes - 11)) 0x00" \
  valid_oaep=32 valid_oaep=$((size_bytes - 66))
else
case $size in
  1024)
    PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
    -c rsa1024/cert.pem -o rsa1024_repeat \
    --repeat ${repeat} --verbose \
    no_structure no_padding=48 signature_padding=8 \
    valid_repeated_byte_payload="118 0xff" \
    valid_repeated_byte_payload="118 0x01" \
    valid=48 header_only \
    no_header_with_payload=48 zero_byte_in_padding="48 4" \
    valid=0 valid=118
    ;;
  2048)
    PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
    -c rsa2048/cert.pem -o rsa2048_repeat \
    --repeat ${repeat} --verbose \
    no_structure no_padding=48 signature_padding=8 \
    valid_repeated_byte_payload="246 0xff" \
    valid_repeated_byte_payload="246 0x01" \
    valid=48 header_only \
    no_header_with_payload=48 zero_byte_in_padding="48 4" \
    valid=0 valid=192 valid=246
    ;;
  4096)
    PYTHONPATH=tlsfuzzer ./marvin-venv/bin/python ./step2.py \
    -c rsa4096/cert.pem -o rsa4096_repeat \
    --repeat ${repeat} --verbose \
    no_structure no_padding=48 signature_padding=8 \
    valid_repeated_byte_payload="502 0xff" \
    valid_repeated_byte_payload="502 0x01" \
    valid=48 header_only \
    no_header_with_payload=48 zero_byte_in_padding="48 4" \
    valid=0 valid=192 valid=502
    ;;
esac
fi

# Run decryptions and analyze data
echo "Starting decryption"
./example/rust-crypto/target/release/rust-crypto \
    -i rsa${size}_repeat/ciphers.bin \
    -o rsa${size}_repeat/raw_times.csv -k rsa${size}/pkcs8.pem -n $size_bytes -m $mode
echo "Decryptions finished"
PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/extract.py \
-l rsa${size}_repeat/log.csv --raw-times rsa${size}_repeat/raw_times.csv \
-o rsa${size}_repeat/ \
--clock-frequency 1000
if [[ $lean == 1 ]]; then
  # Keep only what a merged analysis needs; the ciphertexts are 3 GB per million repetitions.
  mkdir -p ~/marvin-toolkit/outputs/results
  cp rsa${size}_repeat/timing.csv harness-deps.txt ~/marvin-toolkit/outputs/results/
  rm -rf rsa${size}_repeat
  exit 0
fi
# The toolkit's analysis exits non-zero when it detects a side channel. That status is the
# result of the run, but the results are copied out first.
analyse() {
  PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py -o "$1" --verbose
}
status=0
if [[ "$mode" == oaep ]]; then
  # The verdict for OAEP is the toolkit's test over the classes that OAEP rejects, which are
  # the toolkit's own OAEP classes. The analysis of all classes, with the two valid ones, is
  # kept for information: a valid ciphertext is expected to differ from a rejected one, and
  # OAEP reports that outcome to the caller anyway.
  analyse rsa${size}_repeat/ || echo "All classes (informational): the analysis exited with status $?"
  mkdir -p rsa${size}_repeat/rejected-only
  cols=$(head -1 rsa${size}_repeat/timing.csv | tr ',' '\n' | grep -n -v '^valid_oaep' | cut -d: -f1 | paste -sd, -)
  cut -d, -f"$cols" rsa${size}_repeat/timing.csv > rsa${size}_repeat/rejected-only/timing.csv
  echo "OAEP verdict: analysis of the rejected classes"
  analyse rsa${size}_repeat/rejected-only/ || status=$?
else
  analyse rsa${size}_repeat/ || status=$?
fi

# Copy over the keys and the results, if the results directory exists
if [[ -d ~/marvin-toolkit/outputs ]]; then
  [[ -d ~/marvin-toolkit/outputs/keys ]] || cp -r rsa${size} ~/marvin-toolkit/outputs/keys
  cp -r rsa${size}_repeat ~/marvin-toolkit/outputs/results
  cp harness-deps.txt ~/marvin-toolkit/outputs/results/harness-deps.txt
fi
exit $status
