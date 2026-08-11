#!/usr/bin/env bash
#
# make_manifest.sh — hash the evidence and emit evidence_manifest.json
#
# WHY HASHES: a log file can be quietly edited. A sha256 is a
# fingerprint — change one character in the file and the fingerprint
# changes completely. Publishing the fingerprint at collection time
# is how you prove later that nothing was touched.
#
# Usage (from the directory containing evidence_11b/):
#   ./make_manifest.sh
#   INJECTED_BY=security_group ./make_manifest.sh
#
set -euo pipefail

EVIDENCE_DIR="${EVIDENCE_DIR:-evidence_11b}"
STUDENT_NAME="${STUDENT_NAME:-Jerome}"
STUDENT_EMAIL="${STUDENT_EMAIL:-firstofmyname5802@outlook.com}"
STUDENT_CLASS="${STUDENT_CLASS:-SEIR-I}"

INCIDENT_TYPE="${INCIDENT_TYPE:-Lambda-RDS connectivity failure}"
INJECTED_BY="${INJECTED_BY:-security_group}"   # security_group | secret | unknown
INITIAL_SYMPTOM="${INITIAL_SYMPTOM:-API returned non-200}"

[[ -d "$EVIDENCE_DIR" ]] || { echo "ERROR: $EVIDENCE_DIR not found. Run from the dir that contains it." >&2; exit 1; }

# The six files the lab spec requires by name.
REQUIRED=(
  invoke_baseline.json
  invoke_failure.json
  invoke_recovery.json
  logs_tail.out
  sg_before_revoke_3306.out
  sg_after_restore.out
)

# ---- 1. Completeness check BEFORE hashing --------------------
# Better to be told a file is missing now than to submit a manifest
# with a hole in it.
missing=()
for f in "${REQUIRED[@]}"; do
  [[ -s "${EVIDENCE_DIR}/${f}" ]] || missing+=("$f")
done

if (( ${#missing[@]} > 0 )); then
  echo "MISSING or EMPTY required evidence:"
  printf '  - %s\n' "${missing[@]}"
  echo
  echo "Reminder of which phase produces what:"
  echo "  baseline -> invoke_baseline.json, sg_before_revoke_3306.out"
  echo "  failure  -> invoke_failure.json,  sg_after_revoke_3306.out"
  echo "  recovery -> invoke_recovery.json, sg_after_restore.out"
  echo "  all three append to logs_tail.out"
  exit 2
fi

# ---- 2. Hash everything (not just the required six) ----------
# hashes.txt covers the whole pack; the manifest lists the required
# six. Extra evidence is still fingerprinted and still defensible.
( cd "$EVIDENCE_DIR" && sha256sum $(ls -A | grep -v '^hashes.txt$' | sort) > hashes.txt )
echo "Wrote ${EVIDENCE_DIR}/hashes.txt ($(wc -l < "${EVIDENCE_DIR}/hashes.txt") files)"

# ---- 3. Build the manifest -----------------------------------
GENERATED_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
MANIFEST="${EVIDENCE_DIR}/evidence_manifest.json"

{
  echo '{'
  echo '  "schema_version": "1.0",'
  echo '  "lab": "SEIR-I Lab 11B",'
  echo "  \"generated_utc\": \"${GENERATED_UTC}\","
  echo '  "student": {'
  echo "    \"name\": \"${STUDENT_NAME}\","
  echo "    \"email\": \"${STUDENT_EMAIL}\","
  echo "    \"class\": \"${STUDENT_CLASS}\""
  echo '  },'
  echo '  "incident": {'
  echo "    \"type\": \"${INCIDENT_TYPE}\","
  echo "    \"injected_by\": \"${INJECTED_BY}\","
  echo "    \"initial_symptom\": \"${INITIAL_SYMPTOM}\""
  echo '  },'
  echo '  "evidence_files": ['
  last=$(( ${#REQUIRED[@]} - 1 ))
  for i in "${!REQUIRED[@]}"; do
    f="${REQUIRED[$i]}"
    h="$(sha256sum "${EVIDENCE_DIR}/${f}" | awk '{print $1}')"
    comma=","; [[ "$i" -eq "$last" ]] && comma=""
    printf '    {\n      "file": "%s",\n      "sha256": "%s"\n    }%s\n' "$f" "$h" "$comma"
  done
  echo '  ]'
  echo '}'
} > "$MANIFEST"

# ---- 4. Validate it is real JSON -----------------------------
# Never submit a manifest you have not parsed. A trailing comma
# turns your proof into a syntax error.
if command -v python >/dev/null 2>&1; then PY=python; else PY=python3; fi
"$PY" -c "import json,sys; json.load(open(sys.argv[1])); print('JSON valid')" "$MANIFEST"

echo "Wrote $MANIFEST"
echo
echo "Verify anytime with:  ( cd $EVIDENCE_DIR && sha256sum -c hashes.txt )"
