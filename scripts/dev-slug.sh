#!/bin/sh
# Print the dev deployment suffix ("dev-<slug>") for a branch name.
#
# Output satisfies infra's deployment_suffix validation: lowercase
# [a-z0-9-], no leading/trailing hyphen, <= 23 chars — which keeps the
# service-account account_id ("tee-ex-<suffix>", GCP limit 30) valid for
# arbitrarily long branch names. Long slugs are truncated and given a short
# hash of the full branch name so distinct branches can't collide.
#
# Usage: dev-slug.sh [branch]   (defaults to the current git branch)
set -eu

branch=${1:-$(git branch --show-current)}
[ -n "$branch" ] || { echo "dev-slug: not on a branch (detached HEAD?)" >&2; exit 1; }

slug=$(printf '%s' "$branch" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' \
  | sed -e 's/--*/-/g' -e 's/^-*//' -e 's/-*$//')

# "dev-" (4) + slug must stay within 23 chars, so slug <= 19.
if [ ${#slug} -gt 19 ]; then
  hash=$(printf '%s' "$branch" | git hash-object --stdin | cut -c1-6)
  slug="$(printf '%s' "$slug" | cut -c1-12 | sed 's/-*$//')-$hash"
fi

[ -n "$slug" ] || { echo "dev-slug: branch '$branch' sanitizes to nothing" >&2; exit 1; }
printf 'dev-%s\n' "$slug"
