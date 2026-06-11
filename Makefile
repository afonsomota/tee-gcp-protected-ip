# Release pipeline entrypoints (issue 012). `make image` is both the
# canonical release build and the verify-it-yourself rebuild; see
# docs/spikes/001-deterministic-oci-digest.md for why determinism is the
# trust anchor.
#
# Variables:
#   PROJECT_ID    GCP project (required for push/deploy/destroy)
#   REGION        Artifact Registry / deploy region   (default europe-west4)
#   REPOSITORY    Artifact Registry repository id     (default tee-example)
#   TAG           image tag for push                  (default release)
#   IMAGE_DIGEST  digest to deploy/verify (default: dist/image-digest.txt)

REGION       ?= europe-west4
REPOSITORY   ?= tee-example
TAG          ?= release
IMAGE_DIGEST ?= $(shell cat dist/image-digest.txt 2>/dev/null)
IMAGE_REPO    = $(REGION)-docker.pkg.dev/$(PROJECT_ID)/$(REPOSITORY)/launcher
CRANE        ?= $(firstword $(wildcard dist/tools/crane-*) crane)

.PHONY: image digest push deploy verify destroy clean require-project require-digest

## image: deterministic release build -> digest D in dist/image-digest.txt
image:
	scripts/build-image.sh

digest:
	@cat dist/image-digest.txt

require-project:
	@test -n "$(PROJECT_ID)" || { echo "PROJECT_ID is required (make $(MAKECMDGOALS) PROJECT_ID=...)"; exit 1; }

require-digest:
	@test -n "$(IMAGE_DIGEST)" || { echo "IMAGE_DIGEST is empty; run 'make image' first or pass IMAGE_DIGEST=sha256:..."; exit 1; }

## push: push dist/oci-layout by digest to Artifact Registry, assert D survived
push: require-project require-digest
	$(CRANE) push dist/oci-layout $(IMAGE_REPO):$(TAG)
	@pushed=$$($(CRANE) digest $(IMAGE_REPO):$(TAG)); \
	if [ "$$pushed" != "$(IMAGE_DIGEST)" ]; then \
	  echo "pushed digest $$pushed != expected $(IMAGE_DIGEST)"; exit 1; \
	fi; \
	echo "pushed $(IMAGE_REPO)@$$pushed"

## deploy: pin IMAGE_DIGEST into the Confidential Space CVM config and apply.
# The same Terraform root will own the KMS / workload-identity attestation
# policy once issues 004/007 land; because that policy is keyed on
# var.image_digest, this target then also rotates KMS access to the new
# digest (old digests stop being admitted).
deploy: require-project require-digest
	terraform -chdir=infra init -input=false
	terraform -chdir=infra apply -var project_id=$(PROJECT_ID) -var image_digest=$(IMAGE_DIGEST)

## verify: check the live attestation token binds to IMAGE_DIGEST
verify: require-digest
	@ip=$$(terraform -chdir=infra output -raw external_ip); \
	./scripts/verify-attestation.py --url "http://$$ip:8080" --image-digest "$(IMAGE_DIGEST)"

destroy: require-project require-digest
	terraform -chdir=infra destroy -var project_id=$(PROJECT_ID) -var image_digest=$(IMAGE_DIGEST)

clean:
	rm -rf dist
