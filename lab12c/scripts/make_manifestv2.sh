#!/usr/bin/env bash
#
# make_manifest.sh — validate the evidence pack, then hash it and
#                    emit evidence_manifest.json
#
# WHY HASHES: a log file can be quietly edited. A sha256 is a
# fingerprint — change one character and the fingerprint changes
# completely. Publishing fingerprints at collection time is how you
# prove later that nothing was touched.
#
# WHY THE GATES BELOW: hashes prove files weren't ALTERED. They do
# nothing about files that are authentic but tell a false story —
# e.g. a stale invoke_recovery.json left over from an earlier cycle,
# timestamped BEFORE the failure it supposedly recovered from. Valid
# JSON, correct hashes, impossible narrative. That is the failure
# mode these gates exist to catch.
#
# Usage (from the directory containing evidence_11b/):
#   ./make_manifest.sh
#   INJECTED_BY=security_group ./make_manifest.sh
#   SKIP_CHRONOLOGY=1 ./make_manifest.sh    # escape hatch, disclose if used
#
set -euo pipefail

EVIDENCE_DIR="${EVIDENCE_DIR:-evidence_11b}"
STUDENT_NAME="${STUDENT_NAME:-Jerome}"
STUDENT_EMAIL="${STUDENT_EMAIL:-firstofmyname5802@gmail.com}"
STUDENT_CLASS="${STUDENT_CLASS:-SEIR-I}"

INCIDENT_TYPE="${INCIDENT_TYPE:-Lambda-RDS connectivity failure}"
INJECTED_BY="${INJECTED_BY:-security_group}"   # security_group | secret | unknown
INITIAL_SYMPTOM="${INITIAL_SYMPTOM:-API returned non-200}"
SKIP_CHRONOLOGY="${SKIP_CHRONOLOGY:-0}"

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

fail=0
problem() { echo "  ✗ $*"; fail=1; }
ok()      { echo "  ✓ $*"; }

# ==================================================================
# GATE 1 — Completeness
# ==================================================================
echo "GATE 1: required files present and non-empty"
missing=()
for f in "${REQUIRED[@]}"; do
  [[ -s "${EVIDENCE_DIR}/${f}" ]] || missing+=("$f")
done

if (( ${#missing[@]} > 0 )); then
  for f in "${missing[@]}"; do problem "missing or empty: $f"; done
  echo
  echo "Which phase produces what:"
  echo "  baseline -> invoke_baseline.json, sg_before_revoke_3306.out"
  echo "  failure  -> invoke_failure.json,  sg_after_revoke_3306.out"
  echo "  recovery -> invoke_recovery.json, sg_after_restore.out"
  echo "  all three append to logs_tail.out"
  exit 2
fi
ok "all ${#REQUIRED[@]} required files present"

# ==================================================================
# GATE 2 — Chronology
# ==================================================================
# ISO-8601 UTC strings sort correctly as plain text, so a string
# comparison is a valid time comparison here.
echo
echo "GATE 2: chronology (baseline < failure < recovery)"
if [[ "$SKIP_CHRONOLOGY" == "1" ]]; then
  echo "  ! SKIPPED via SKIP_CHRONOLOGY=1 — you must disclose this in human_notes_11b.md"
else
  ts_missing=0
  for p in baseline failure recovery; do
    [[ -s "${EVIDENCE_DIR}/t_${p}.txt" ]] || { problem "no timestamp file t_${p}.txt"; ts_missing=1; }
  done

  if (( ts_missing == 0 )); then
    T_BASE="$(tr -d '[:space:]' < "${EVIDENCE_DIR}/t_baseline.txt")"
    T_FAIL="$(tr -d '[:space:]' < "${EVIDENCE_DIR}/t_failure.txt")"
    T_REC="$(tr -d '[:space:]'  < "${EVIDENCE_DIR}/t_recovery.txt")"
    printf '  baseline %s\n  failure  %s\n  recovery %s\n' "$T_BASE" "$T_FAIL" "$T_REC"

    if [[ "$T_BASE" < "$T_FAIL" ]]; then ok "baseline precedes failure"
    else problem "baseline ($T_BASE) does not precede failure ($T_FAIL)"; fi

    if [[ "$T_FAIL" < "$T_REC" ]]; then ok "failure precedes recovery"
    else problem "recovery ($T_REC) predates the failure ($T_FAIL) — STALE recovery evidence from an earlier cycle"; fi
  fi
fi

# ==================================================================
# GATE 3 — The story the HTTP codes tell
# ==================================================================
echo
echo "GATE 3: HTTP codes (200 / non-200 / 200)"
code_of() { tr -d '[:space:]' < "${EVIDENCE_DIR}/invoke_${1}.http_code" 2>/dev/null || echo "??"; }
C_BASE="$(code_of baseline)"; C_FAIL="$(code_of failure)"; C_REC="$(code_of recovery)"
printf '  baseline=%s  failure=%s  recovery=%s\n' "$C_BASE" "$C_FAIL" "$C_REC"

[[ "$C_BASE" == "200" ]] && ok "baseline healthy" || problem "baseline is $C_BASE, expected 200 — cannot prove the system was ever healthy"
[[ "$C_FAIL" != "200" && "$C_FAIL" != "??" ]] && ok "failure proven ($C_FAIL)" || problem "failure is $C_FAIL — incident not proven"
[[ "$C_REC" == "200" ]] && ok "recovery proven" || problem "recovery is $C_REC, expected 200 — recovery not proven"

# ==================================================================
# GATE 4 — Security group state matches the narrative
# ==================================================================
echo
echo "GATE 4: security group snapshots"
# Rough but effective: the before/after-restore snapshots should
# contain a 3306 rule; the post-revoke snapshot should not.
grep -q '"FromPort": 3306' "${EVIDENCE_DIR}/sg_before_revoke_3306.out" \
  && ok "sg_before_revoke_3306.out shows a 3306 rule" \
  || problem "sg_before_revoke_3306.out has no 3306 rule — baseline was already broken?"

grep -q '"FromPort": 3306' "${EVIDENCE_DIR}/sg_after_restore.out" \
  && ok "sg_after_restore.out shows a 3306 rule" \
  || problem "sg_after_restore.out has no 3306 rule — rule was not actually restored"

if [[ -s "${EVIDENCE_DIR}/sg_after_revoke_3306.out" ]]; then
  grep -q '"FromPort": 3306' "${EVIDENCE_DIR}/sg_after_revoke_3306.out" \
    && problem "sg_after_revoke_3306.out still shows a 3306 rule — was it really revoked?" \
    || ok "sg_after_revoke_3306.out shows the rule absent"
fi

if (( fail != 0 )); then
  echo
  echo "REFUSING to write a manifest for an inconsistent evidence pack."
  echo "Re-run the affected phase. Do not re-word the story."
  exit 3
fi

# ==================================================================
# Hash everything
# ==================================================================
echo
( cd "$EVIDENCE_DIR" && sha256sum $(ls -A | grep -vE '^(hashes\.txt|evidence_manifest\.json)$' | sort) > hashes.txt )
echo "Wrote ${EVIDENCE_DIR}/hashes.txt ($(wc -l < "${EVIDENCE_DIR}/hashes.txt") files)"

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

# Never submit a manifest you have not parsed. A trailing comma
# turns your proof into a syntax error.
if command -v python >/dev/null 2>&1; then PY=python; else PY=python3; fi
"$PY" -c "import json,sys; json.load(open(sys.argv[1])); print('JSON valid')" "$MANIFEST"

# Prove the hashes we just wrote actually verify.
( cd "$EVIDENCE_DIR" && sha256sum -c hashes.txt >/dev/null && echo "hashes verify" )

echo "Wrote $MANIFEST"
echo
echo "ALL GATES PASSED."
echo "Note: the manifest lists the six spec-required files; every other"
echo "file in the pack (CloudTrail, terraform plans, alarms) is still"
echo "fingerprinted in hashes.txt."
echo "Re-verify anytime:  ( cd $EVIDENCE_DIR && sha256sum -c hashes.txt )"