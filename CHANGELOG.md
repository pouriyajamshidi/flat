# Changelog

## Unreleased

### Fixed

- Stale flow table entries are now all pruned. Pruning used to stop at the first fresh entry, so the table could grow without bound.
- Only TCP SYN and SYN/ACK packets are sent to user space. Other TCP packets used to fall through to the UDP path and were sent up for nothing.
- `-ip` and `-port` used together now match flows that have both, instead of either.
- The qdisc is removed when startup fails part way, including when the ring buffer reader cannot be opened.
- UDP packets with less than 12 bytes of payload are no longer dropped.
- IPv4 packets with IP options now report the correct ports.
- The rlimit log message shows the values that are actually set.
- Clearer error for out of range `-port` values.
- The shutdown message names the signal that was caught (SIGINT or SIGTERM).
- Test packets use a unicast destination MAC and a valid IPv4 header, so the eBPF tests exercise the parser instead of being dropped at the unicast check.
- README: fixed the `git clone` command and listed the build dependencies.
