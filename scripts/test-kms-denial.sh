#!/usr/bin/env bash
# Negative test for attestation-gated artifact delivery (issue #7).
#
# Proves the KMS gate holds even when everything *except* the attestation is
# identical: boots a plain (non-confidential) VM with the SAME workload
# service account and the SAME cloud-platform scope as the enclave CVM, and
# has it attempt to unwrap the real weights DEK. The only credential it can
# present is the service-account token — there is no Confidential Space
# attestation JWT to exchange at STS — and the key grants decrypt exclusively
# to the attested workload-identity principalSet, so KMS must answer 403.
#
# PASS = KMS returns 403 on the plain VM. The VM is deleted on exit.
#
# Prerequisites: the main infra root is applied (the workload service account
# must exist) and the weights are provisioned (scripts/provision-weights.py).
#
# Usage:
#   ./test-kms-denial.sh PROJECT_ID MANIFEST_OBJECT [ZONE]
#   e.g. ./test-kms-denial.sh my-project weights/model.gguf.manifest.json
set -euo pipefail

PROJECT="${1:?usage: test-kms-denial.sh PROJECT_ID MANIFEST_OBJECT [ZONE]}"
OBJECT="${2:?usage: test-kms-denial.sh PROJECT_ID MANIFEST_OBJECT [ZONE]}"
ZONE="${3:-europe-west4-a}"

BUCKET="$PROJECT-tee-example-artifacts"
SERVICE_ACCOUNT="tee-example-workload@$PROJECT.iam.gserviceaccount.com"
VM="kms-denial-test-$RANDOM"

log() { printf '>> %s\n' "$*" >&2; }

log "reading manifest gs://$BUCKET/$OBJECT"
MANIFEST="$(gcloud storage cat "gs://$BUCKET/$OBJECT" --project "$PROJECT")"
WRAPPED_DEK="$(printf '%s' "$MANIFEST" | python3 -c 'import json,sys; print(json.load(sys.stdin)["wrapped_dek"])')"
KMS_KEY="$(printf '%s' "$MANIFEST" | python3 -c 'import json,sys; print(json.load(sys.stdin)["kms_key"])')"
log "key under test: $KMS_KEY"

# Runs on the plain VM: service-account token from the metadata server, then
# a KMS :decrypt of the real wrapped DEK; the HTTP status goes to the serial
# console where we poll for it.
STARTUP="$(mktemp)"
trap 'rm -f "$STARTUP"' EXIT
cat > "$STARTUP" <<'EOF'
#!/bin/bash
attr() { curl -sf -H 'Metadata-Flavor: Google' "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"; }
TOKEN=$(curl -sf -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
CODE=$(curl -s -o /tmp/kms-response -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"ciphertext\":\"$(attr wrapped-dek)\"}" \
  "https://cloudkms.googleapis.com/v1/$(attr kms-key):decrypt")
echo "KMS_DENIAL_TEST result code=$CODE"
cat /tmp/kms-response
EOF

log "creating plain VM $VM (same SA + scopes as the enclave, no attestation)"
cleanup() {
  rm -f "$STARTUP"
  log "deleting $VM"
  gcloud compute instances delete "$VM" --project "$PROJECT" --zone "$ZONE" --quiet || true
}
trap cleanup EXIT

gcloud compute instances create "$VM" \
  --project "$PROJECT" --zone "$ZONE" \
  --machine-type e2-small \
  --image-family debian-12 --image-project debian-cloud \
  --service-account "$SERVICE_ACCOUNT" --scopes cloud-platform \
  --metadata "wrapped-dek=$WRAPPED_DEK,kms-key=$KMS_KEY" \
  --metadata-from-file "startup-script=$STARTUP" \
  >/dev/null

log "polling serial console for the result"
for _ in $(seq 1 30); do
  sleep 10
  RESULT="$(gcloud compute instances get-serial-port-output "$VM" \
    --project "$PROJECT" --zone "$ZONE" 2>/dev/null \
    | grep -o 'KMS_DENIAL_TEST result code=[0-9]*' | tail -n1 || true)"
  [ -n "$RESULT" ] && break
done

case "${RESULT:-}" in
  *code=403)
    log "PASS: KMS denied decrypt to the non-attested VM (403)"
    exit 0 ;;
  *code=200)
    log "FAIL: KMS decrypted the DEK for a NON-ATTESTED VM — the gate is open"
    exit 1 ;;
  *code=*)
    log "FAIL: unexpected KMS status: $RESULT (expected 403)"
    exit 1 ;;
  *)
    log "FAIL: no result on the serial console after 5 minutes"
    exit 1 ;;
esac
