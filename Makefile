.PHONY: build run app kill test clean

PORT ?= 8080

# go-webui requires CGO (macOS WebKit / Cocoa frameworks).
build:
	@mkdir -p build
	@if [ ! -f build/gofing-notify ] || [ scripts/notify.m -nt build/gofing-notify ]; then \
		echo "Compiling notification helper..."; \
		clang -O2 -framework Cocoa -Wno-deprecated-declarations scripts/notify.m -o build/gofing-notify; \
	fi
	CGO_ENABLED=1 go build -o gofing .

run: build
	./gofing -port $(PORT)

app:
	@./scripts/build-app.sh

kill:
	@PIDS=$$(pgrep -f 'Gofing\.app/Contents/MacOS/Gofing|/gofing-bin$$|/gofing -port|^\./gofing' 2>/dev/null || true); \
	PORT_PIDS=$$(lsof -tiTCP:$(PORT) -sTCP:LISTEN 2>/dev/null || true); \
	ALL=$$(echo "$$PIDS $$PORT_PIDS" | tr ' ' '\n' | sort -u | grep -v '^$$' || true); \
	if [ -n "$$ALL" ]; then echo "Stopping: $$ALL"; kill $$ALL 2>/dev/null || true; sleep 1; \
	  for p in $$ALL; do kill -0 $$p 2>/dev/null && kill -9 $$p 2>/dev/null || true; done; \
	  echo "Stopped."; else echo "No Gofing process found on port $(PORT)."; fi

test:
	go test -v ./...

clean:
	rm -f gofing
	rm -rf Gofing.app
	rm -f build/gofing-notify
