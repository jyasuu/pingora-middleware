.PHONY: build run test lint docker-build docker-up docker-down clean \
        integration-up integration-down integration-test

## Build the release binary
build:
	cargo build --release

## Run locally (requires Redis + INTERNAL_SERVICE_TOKEN env var)
run:
	@test -f .env && export $$(cat .env | xargs) || true; \
	RUST_LOG=info cargo run --bin proxy

## Run unit + token tests
test:
	cargo test -- --nocapture

## Clippy + format check
lint:
	cargo clippy -- -D warnings
	cargo fmt --check

## Build the Docker image
docker-build:
	docker build -f deploy/docker/Dockerfile -t pingora-middleware:latest .

## Start the production stack (Pingora + Redis + mock service)
docker-up:
	docker compose -f deploy/docker/docker-compose.yml --env-file .env up -d

## Tear down the production stack
docker-down:
	docker compose -f deploy/docker/docker-compose.yml down

## ── Integration tests (OAuth2 + Pingora + whoami) ───────────────────────────

## Start the integration-test stack (mock-jwks + whoami + redis + pingora)
integration-up:
	docker compose -f deploy/docker/docker-compose.integration.yml up --build -d

## Tear down the integration-test stack and remove volumes
integration-down:
	docker compose -f deploy/docker/docker-compose.integration.yml down -v

## Run all E2E tests (starts stack, runs tests, tears down)
integration-test: integration-up
	@echo "Waiting for Pingora :6191 to be ready..."
	@for i in $$(seq 1 60); do \
	  STATUS=$$(curl -s -o /dev/null -w "%{http_code}" http://localhost:6191/api/healthz 2>/dev/null); \
	  if [ "$$STATUS" = "401" ]; then echo "Pingora is up (got 401)"; break; fi; \
	  echo "  attempt $$i/60 — status=$$STATUS, retrying..."; sleep 1; \
	done
	PINGORA_URL=http://localhost:6191 \
	MOCK_JWKS_URL=http://localhost:8888 \
	cargo test --test integration_test_e2e -- --nocapture
	$(MAKE) integration-down

## Remove build artefacts
clean:
	cargo clean
