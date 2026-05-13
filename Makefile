.PHONY: build test run web-build

build:
	go build ./...

test:
	go test ./...

run:
	go run . serve

web-build:
	cd web && npm run build

