SHELL := /bin/bash

APP_NAME     := recco-mock-tpp
TPP_HOST     := recco-tpp.test
TPP_PORT     := 8443
DEVCERT_DIR  := devcerts

.PHONY: devcerts
devcerts:
	mkdir -p $(DEVCERT_DIR)
	@if ! command -v mkcert >/dev/null 2>&1; then \
  		echo "mkcert not found."; \
		exit 1; \
	fi
	mkcert -install
	@echo "Creating certificates for TPP service ($(TPP_HOST))..."
	mkcert -cert-file $(DEVCERT_DIR)/$(TPP_HOST).pem -key-file $(DEVCERT_DIR)/$(TPP_HOST)-key $(TPP_HOST)
	@echo "Certificates created successfully!"
	@echo "TPP Service: $(DEVCERT_DIR)/$(TPP_HOST).pem + $(DEVCERT_DIR)/$(TPP_HOST)-key"

.PHONY: test
test:
	go test ./... -race -count=1 -covermode=atomic -coverprofile=coverage.out -v

.PHONY: build
build:
	docker build -t $(APP_NAME):latest .

.PHONY: up
up:
	@if [ -z "$(KID)" ]; then \
		echo "ERROR: missing kid. Usage: make up KID=<your-kid>"; \
		exit 1; \
	fi
	@echo "Starting with SIGNING_KEY_ID=$(KID)"
	SIGNING_KEY_ID=$(KID) docker compose up -d --build

.PHONY: down
down:
	SIGNING_KEY_ID="" docker compose down -v

.PHONY: logs
logs:
	docker compose logs -f

.PHONY: run-local
run-local:
	@set -a; source .env; set +a; go run ./cmd/server
