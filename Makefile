# Release pipeline entrypoints (issue 012). `make image` is both the
# canonical release build and the verify-it-yourself rebuild; see
# docs/spikes/001-deterministic-oci-digest.md for why determinism is the
# trust anchor.
#
# Variables:
#   PROJECT_ID    GCP project (required for push/deploy/destroy/dev-*)
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

.PHONY: image digest push deploy verify destroy dev-deploy dev-destroy dev-list clean require-project require-digest

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
	terraform -chdir=infra init -input=false \
	  -backend-config="bucket=$(PROJECT_ID)-tfstate" -backend-config="prefix=cvm"
	terraform -chdir=infra workspace select default
	terraform -chdir=infra apply -var project_id=$(PROJECT_ID) -var image_digest=$(IMAGE_DIGEST)

## verify: check the live attestation token binds to IMAGE_DIGEST
verify: require-digest
	@ip=$$(terraform -chdir=infra output -raw external_ip); \
	./scripts/verify-attestation.py --url "http://$$ip:8080" --image-digest "$(IMAGE_DIGEST)"

destroy: require-project require-digest
	terraform -chdir=infra workspace select default
	terraform -chdir=infra destroy -var project_id=$(PROJECT_ID) -var image_digest=$(IMAGE_DIGEST)

## dev-deploy: per-branch dev CVM alongside prod (issue #28).
# Deployment suffix dev-<slug> comes from the current branch
# (scripts/dev-slug.sh); state lives in the Terraform workspace of the same
# name, so prod (default workspace) is untouched. The image goes through the
# buildx path — non-reproducible digest, dev only. The CVM gets an ephemeral
# external IP (printed at the end); prod keeps the static one.
dev-deploy: require-project
	@suffix=$$(scripts/dev-slug.sh); \
	image=$(IMAGE_REPO):$$suffix; \
	echo "==> dev deployment $$suffix"; \
	docker buildx build --platform linux/amd64 -t $$image --push launcher/; \
	digest=$$(docker buildx imagetools inspect $$image --format '{{json .Manifest.Digest}}' | tr -d '"'); \
	terraform -chdir=infra init -input=false \
	  -backend-config="bucket=$(PROJECT_ID)-tfstate" -backend-config="prefix=cvm"; \
	terraform -chdir=infra workspace select -or-create $$suffix; \
	terraform -chdir=infra apply -var project_id=$(PROJECT_ID) -var image_digest=$$digest -var deployment_suffix=$$suffix \
	  || { terraform -chdir=infra workspace select default; exit 1; }; \
	ip=$$(terraform -chdir=infra output -raw external_ip); \
	terraform -chdir=infra workspace select default; \
	echo "==> $$suffix up: http://$$ip:8080 (ephemeral IP)"; \
	echo "    verify: ./scripts/verify-attestation.py --url http://$$ip:8080 --image-digest $$digest"; \
	echo "    tear down: make dev-destroy PROJECT_ID=$(PROJECT_ID)"

## dev-destroy: tear down this branch's dev deployment only
dev-destroy: require-project
	@suffix=$$(scripts/dev-slug.sh); \
	terraform -chdir=infra workspace select $$suffix \
	  || { echo "no workspace '$$suffix' — nothing deployed for this branch?"; exit 1; }; \
	terraform -chdir=infra destroy -var project_id=$(PROJECT_ID) -var deployment_suffix=$$suffix \
	  || { terraform -chdir=infra workspace select default; exit 1; }; \
	terraform -chdir=infra workspace select default; \
	terraform -chdir=infra workspace delete $$suffix

## dev-list: list dev deployment workspaces (each may be a running CVM — cost)
dev-list:
	@terraform -chdir=infra workspace list | grep dev- \
	  || echo "no dev deployment workspaces"

clean:
	rm -rf dist
