#!/bin/bash
# Run the Marvin harness as several pinned processes at once and merge their timings.
#
# One key pair is generated and shared by every process. Each process generates its own
# ciphertexts, decrypts them on its own CPU core, and writes its own timing.csv. The rows are
# then concatenated and analysed as one data set. The toolkit's tests compare classes within
# a row, so rows from independent processes can be combined.
#
# Usage: ./parallel-run.sh -c CORES -n TOTAL [-b ROUNDS] [-m MODE] [-s SIZE] [-o OUTDIR] [-i IMAGE] [-r SRC]
#   -c CORES   CPU cores to use, one process each, e.g. "1-15" or "2,4,6"
#   -n TOTAL   total repetitions per class across all processes
#   -b ROUNDS  split the work into this many rounds, keeping only the timings of each round
#              (default 1). Ciphertexts take 3 GB per million repetitions, so a large run
#              needs rounds to fit on disk.
#   -a         skip the merged analysis (only merge the timings)
#   -m MODE    pkcs1v15 (default) or oaep
#   -s SIZE    RSA key size (default 2048)
#   -o OUTDIR  output directory (default ./outputs-parallel)
#   -i IMAGE   harness image (default marvin:latest)
#   -r SRC     sad-rsa source tree to test (default: the parent of this directory)
set -euo pipefail

cd "$(dirname "$0")"
cores=""; total=""; rounds=1; analyse=1; mode=pkcs1v15; size=2048; out=outputs-parallel; image=marvin:latest
src="$(cd .. && pwd)"
while getopts "c:n:b:am:s:o:i:r:" opt; do
  case $opt in
    c) cores=$OPTARG ;; n) total=$OPTARG ;; b) rounds=$OPTARG ;; a) analyse=0 ;; m) mode=$OPTARG ;; s) size=$OPTARG ;;
    o) out=$OPTARG ;; i) image=$OPTARG ;; r) src=$OPTARG ;;
    *) sed -n '2,20p' "$0"; exit 2 ;;
  esac
done
if [[ -z $cores || -z $total ]]; then sed -n '2,20p' "$0"; exit 2; fi

# Expand "1-3,7" into "1 2 3 7"
list=()
IFS=, read -ra parts <<< "$cores"
for part in "${parts[@]}"; do
  if [[ $part == *-* ]]; then
    for ((c = ${part%-*}; c <= ${part#*-}; c++)); do list+=("$c"); done
  else
    list+=("$part")
  fi
done
procs=${#list[@]}
each=$(( (total + procs * rounds - 1) / (procs * rounds) ))
echo "$procs processes on cores ${list[*]}, $rounds round(s) of $each repetitions per class each ($((each * procs * rounds)) in total)"

mkdir -p "$out"; out="$(cd "$out" && pwd)"
toolkit=/home/rustcrypto/marvin-toolkit
manifest="$(pwd)/Cargo.toml"

# One key for all processes
if [[ ! -f $out/keys/pkcs8.pem ]]; then
  mkdir -p "$out/keygen"; chmod a+rwx "$out/keygen"
  docker run --rm -v "$src":/sad-rsa:ro -v "$manifest":$toolkit/example/rust-crypto/Cargo.toml \
    -v "$out/keygen":$toolkit/outputs "$image" -s "$size" -g > "$out/keygen.log" 2>&1
  mv "$out/keygen/keys" "$out/keys"; rmdir "$out/keygen"
fi

# The pinned processes, one round at a time. Each round's timings are appended to the merged
# file and the round's working files are removed.
mkdir -p "$out/merged" "$out/logs"; chmod a+rwx "$out/merged"
merged="$out/merged/timing.csv"
start_round=1
if [[ -f $out/rounds-done ]]; then start_round=$(( $(cat "$out/rounds-done") + 1 )); fi
if [[ $start_round == 1 ]]; then rm -f "$merged"; fi
for ((r = start_round; r <= rounds; r++)); do
  pids=()
  for c in "${list[@]}"; do
    rm -rf "$out/core-$c"; mkdir -p "$out/core-$c"; chmod a+rwx "$out/core-$c"
    docker run --rm --name "marvin-par-$c" --cpuset-cpus="$c" \
      -v "$src":/sad-rsa:ro -v "$manifest":$toolkit/example/rust-crypto/Cargo.toml \
      -v "$out/keys":$toolkit/rsa$size:ro -v "$out/core-$c":$toolkit/outputs \
      "$image" -s "$size" -n "$each" -m "$mode" -l > "$out/logs/round-$r-core-$c.log" 2>&1 &
    pids+=($!)
  done
  failed=0
  for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
  if [[ $failed == 1 ]]; then echo "ERROR: a process failed in round $r; see $out/logs/" >&2; exit 1; fi

  # Every timing.csv must have the same header
  for c in "${list[@]}"; do
    f="$out/core-$c/results/timing.csv"
    if [[ ! -f $merged ]]; then head -1 "$f" > "$merged"; fi
    if [[ "$(head -1 "$f")" != "$(head -1 "$merged")" ]]; then echo "ERROR: $f has a different header" >&2; exit 1; fi
    tail -n +2 "$f" >> "$merged"
    cp "$out/core-$c/results/harness-deps.txt" "$out/harness-deps.txt"
    rm -rf "$out/core-$c"
  done
  echo "$r" > "$out/rounds-done"
  echo "$(date -u +%FT%TZ) round $r of $rounds done, $(( $(wc -l < "$merged") - 1 )) rows merged"
done

if [[ $analyse == 0 ]]; then exit 0; fi
# The toolkit's analysis exits non-zero when it detects a side channel; that is this script's
# exit status. Extra arguments for the analysis can be passed in ANALYSIS_ARGS, for example
# "--no-conf-interval-plot --no-scatter-plot --no-ecdf-plot --workers 10" for a very large run.
analyse() {
  docker run --rm --entrypoint bash -v "$1":$toolkit/merged "$image" -c \
    "PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py -o merged/ --verbose ${ANALYSIS_ARGS:-}" \
    > "$2" 2>&1
}
status=0
if [[ $mode == oaep ]]; then
  # The verdict for OAEP is the toolkit's test over the classes that OAEP rejects (the
  # toolkit's own OAEP classes). The analysis of all classes is kept for information.
  analyse "$out/merged" "$out/merged-analysis.log" \
    || echo "All classes (informational): the analysis exited with status $?"
  mkdir -p "$out/merged/rejected-only"; chmod a+rwx "$out/merged/rejected-only"
  cols=$(head -1 "$merged" | tr ',' '\n' | grep -n -v '^valid_oaep' | cut -d: -f1 | paste -sd, -)
  cut -d, -f"$cols" "$merged" > "$out/merged/rejected-only/timing.csv"
  analyse "$out/merged/rejected-only" "$out/merged-analysis-rejected-only.log" || status=$?
  echo "OAEP verdict (rejected classes):"
  cat "$out/merged/rejected-only/report.txt"
else
  analyse "$out/merged" "$out/merged-analysis.log" || status=$?
  cat "$out/merged/report.txt"
fi
exit $status
