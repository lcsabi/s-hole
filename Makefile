BINARY  = s-hole
LDFLAGS = -ldflags="-s -w"

# On Windows use: $env:GOOS="linux"; $env:GOARCH="arm64"; go build ...
# or run these targets from WSL / Git Bash.

.PHONY: all pi pi32 linux clean

## all: build for the current OS/architecture
all:
	go build $(LDFLAGS) -o $(BINARY) .

## pi: Raspberry Pi 4 / 5 and any 64-bit ARM board (arm64)
pi:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 .

## pi32: Raspberry Pi 2 / 3 and older 32-bit ARM boards (armv7)
pi32:
	GOOS=linux GOARCH=arm GOARM=7 go build $(LDFLAGS) -o $(BINARY)-linux-armv7 .

## linux: 64-bit x86 Linux (for VMs, cloud, NAS)
linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .

## clean: remove compiled binaries
clean:
	rm -f $(BINARY) $(BINARY)-linux-*
