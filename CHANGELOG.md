# Changelog

## Unreleased

### Changed

- Signal handling uses `signal.NotifyContext`. A second Ctrl+C now exits right away if shutdown hangs.

## v0.6.0

### Changed

- Releases ship `flat_linux_amd64.tar.gz` and `flat_linux_arm64.tar.gz` with a `checksums.txt`. The old `flat.tar.gz` and `flat-greenteagc.tar.gz` are gone, since Green Tea GC is the default since Go 1.26.
- The eBPF code uses `bpf/vmlinux.h` instead of libc and kernel headers, so building only needs `clang`, `llvm`, and `libbpf-dev`. Only little-endian architectures are supported.
- `make` now builds the `flat` binary. Use `make release` to build the release archives.
- Releases are built and published by GitHub Actions when a `v*` tag is pushed.
- The generated eBPF files (`internal/probe/probe_bpf*.go` and `.o`) are no longer in git. Run `go generate ./...` (or `make`) before building.

### Fixed

- The C compiler flags in `go:generate` (`-Wall -Werror` and others) were silently ignored because of a wrong separator (`-` instead of `--`).

- A retransmitted SYN restarts the latency measurement, so the retransmission wait is no longer reported as latency.
- Packets dropped because the ring buffer is full are now counted and logged every 10 seconds, instead of silently missing from the results. Only TCP and UDP packets use ring buffer space now, so other traffic no longer takes room from them.

- Stale flow table entries are now all pruned. Pruning used to stop at the first fresh entry, so the table could grow without bound.
- Only TCP SYN and SYN/ACK packets are sent to user space. Other TCP packets used to fall through to the UDP path and were sent up for nothing.
- `-ip` and `-port` used together now match flows that have both, instead of either.
- The qdisc is removed when startup fails part way, including when the ring buffer reader cannot be opened.
- UDP packets with less than 12 bytes of payload are no longer dropped.
- IPv4 packets with IP options now report the correct ports.
- The rlimit log message shows the values that are actually set.
- Clearer error for out of range `-port` values.
- Stopping the program no longer logs `Failed reading from ringbuf: epoll wait: file already closed`.
- The shutdown message names the signal that was caught (SIGINT or SIGTERM).
- Test packets use a unicast destination MAC and a valid IPv4 header, so the eBPF tests exercise the parser instead of being dropped at the unicast check.
- README: fixed the `git clone` command and listed the build dependencies.
