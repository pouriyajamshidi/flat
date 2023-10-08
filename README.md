# flat

Measure **UDP** and **TCP** flow latency for both **IPv4** and **IPv6** using `eBPF`.

This repo is the companion to my blog posts about eBPF at <https://thegraynode.io/tags/flat/>.

![flat in action](.images/flat.gif)

## Running The Program

Clone the repository.

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

Run it with elevated privileges:

```bash
# Replace eth0 with your desired interface name
sudo ./flat -i eth0
```

## Acknolegments

Heavily inspired by [flowlat](https://github.com/markpash/flowlat).
