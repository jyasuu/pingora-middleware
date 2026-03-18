.PHONY: build run test lint docker-build docker-up docker-down clean

## Build the release binary
build:
	cargo build --release

## Run locally (requires Redis + INTERNAL_SERVICE_TOKEN env var)
run:
	@test -f .env && export $$(cat .env | xargs) || true; \
	RUST_LOG=info cargo run --bin proxy

## Run all tests
test:
	cargo test -- --nocapture

## Clippy + format check
lint:
	cargo clippy -- -D warnings
	cargo fmt --check

## Build the Docker image
docker-build:
	docker build -f deploy/docker/Dockerfile -t pingora-middleware:latest .

## Start the full stack (Pingora + Redis + mock service)
docker-up:
	docker compose -f deploy/docker/docker-compose.yml --env-file .env up -d

## Tear down the stack
docker-down:
	docker compose -f deploy/docker/docker-compose.yml down

## Remove build artefacts
clean:
	cargo clean
