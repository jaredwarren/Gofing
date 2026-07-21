.PHONY: build run test clean

build:
	go build -o gofing .

run: build
	./gofing -port 8080

test:
	go test -v ./...

clean:
	rm -f gofing
