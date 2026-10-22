.PHONY: build-all dev test docker-up clean

build-all:
	cd core/daemon && cargo build --release
	cd control-plane && go build -o control-plane .
	cd apps/dashboard && npm install && npm run build

dev:
	docker compose up --build

test:
	cd core/daemon && cargo test
	cd control-plane && go vet ./... && go test ./...
	cd apps/dashboard && npm run build

docker-up:
	docker compose up --build -d

clean:
	cd core/daemon && cargo clean
	rm -f control-plane/control-plane
	rm -rf apps/dashboard/dist apps/dashboard/node_modules
	docker compose down -v 2>/dev/null || true
