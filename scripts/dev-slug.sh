#!/bin/sh
# Print the dev deployment suffix ("dev-<slug>") for a branch name.
#
# The suffix must satisfy two independent length limits:
#   * service-account account_id "tee-ex-<suffix>" (GCP limit 30) => suffix <= 23.
#   * attestation token `sub` (the instance resource URL) <= 127 bytes, the STS
#     google.subject limit. The sub is
#       https://www.googleapis.com/compute/v1/projects/<project>/zones/<zone>/instances/tee-example-cvm-<suffix>
#     whose fixed part (everything but <project>, <zone>, <suffix>) is 81 bytes.
#     Overflowing it makes every KMS artifact delivery fail the STS token
#     exchange with 400 "google.subject exceeds the 127 byte" (issue #49), so
#     the suffix is bounded by 127 - 81 - len(project) - len(zone) too.
#     Assumption: the sub carries the project *id* (string), not the numeric
#     project number — confirmed by #49's live 400 hitting the limit at exactly
#     the project-id length. If GCP ever emitted the number instead, this
#     budget would track the wrong field and #49 could silently regress.
# Long slugs are truncated and given a short hash of the full branch name so
# distinct branches can't collide.
#
# PROJECT_ID / ZONE (default europe-west4-a, matching infra) tighten the sub
# budget; with PROJECT_ID unset only the 23-char account_id limit applies.
#
# Usage: dev-slug.sh [branch]   (defaults to the current git branch)
set -eu

branch=${1:-$(git branch --show-current)}
[ -n "$branch" ] || { echo "dev-slug: not on a branch (detached HEAD?)" >&2; exit 1; }

slug=$(printf '%s' "$branch" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' \
  | sed -e 's/--*/-/g' -e 's/^-*//' -e 's/-*$//')

# Tightest suffix length allowed by both limits, then minus "dev-" (4) for the slug.
project=${PROJECT_ID:-}
zone=${ZONE:-europe-west4-a}
suffix_max=23
sub_budget=$(( 127 - 81 - ${#project} - ${#zone} ))
[ -n "$project" ] && [ "$sub_budget" -lt "$suffix_max" ] && suffix_max=$sub_budget
slug_max=$(( suffix_max - 4 ))

if [ ${#slug} -gt "$slug_max" ]; then
  # Truncate and append a 6-char hash of the full branch (+ "-") to avoid
  # collisions; needs 7 chars of headroom for the hash to be meaningful.
  [ "$slug_max" -ge 8 ] || { echo "dev-slug: project id / zone leave no room for a slug" >&2; exit 1; }
  hash=$(printf '%s' "$branch" | git hash-object --stdin | cut -c1-6)
  slug="$(printf '%s' "$slug" | cut -c1-"$(( slug_max - 7 ))" | sed 's/-*$//')-$hash"
fi

[ -n "$slug" ] || { echo "dev-slug: branch '$branch' sanitizes to nothing" >&2; exit 1; }
printf 'dev-%s\n' "$slug"
