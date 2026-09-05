.PHONY: build run test clean

PORT ?= 8080

build:
	go build -o gofing .

run: build
	./gofing -port $(PORT)

test:
	go test -v ./...

clean:
	rm -f gofing
