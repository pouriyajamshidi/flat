# flat

Measure **UDP** and **TCP** flow latency for both **IPv4** and **IPv6** using `eBPF`.

This repo is the companion to my blog posts about eBPF at <https://thegraynode.io/tags/flat/>.

![flat in action](.images/flat.gif)

## Running The Program

You can install **flat** in two ways.

1. Download the [pre-compiled binary](#download-the-pre-compiled-binary)
2. Compile from [source](#compile-from-source)

### Download The Pre-compiled Binary

```bash
wget https://github.com/pouriyajamshidi/flat/releases/latest/download/flat
```

Then check out the [examples](#examples).

### Compile From Source

Clone the repository:

```bash
git clone https://github.com/pouriyajamshidi/flat .
```

Change directory to `flat`:

```bash
cd flat
```

While at the root of project directory, to compile the **C** code and generate the helper functions, run:

```bash
go generate ./...
```

Compile the **Go** program:

```bash
go build -ldflags "-s -w" -o flat cmd/flat.go
```

### Examples

Run it with elevated privileges:

```bash
# Replace eth0 with your desired interface name
sudo ./flat -i eth0
# Or
sudo ./flat -i eth0 -ip 1.1.1.1
# Or
sudo ./flat -i eth0 -port 53
# Or
sudo ./flat -i eth0 -ip 1.1.1.1 -port 53
```

## Flags

**flat** supports four flags at the moment:

| flag  | Description                         |
| ----- | ----------------------------------- |
| -i    | interface to attach the probe to    |
| -ip   | IP address to filter on (optional)  |
| -port | Port number to filter on (optional) |
| -h    | Show help message                   |

---

## Acknolegments

Heavily inspired by [flowlat](https://github.com/markpash/flowlat).
