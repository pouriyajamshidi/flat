package probe

import (
	"context"
	"log"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/pouriyajamshidi/flat/clsact"
	"github.com/pouriyajamshidi/flat/internal/flowtable"
	"github.com/pouriyajamshidi/flat/internal/packet"
	"github.com/pouriyajamshidi/flat/internal/types"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/flat.c - -O2  -Wall -Werror -Wno-address-of-packed-member

const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	bpfObjects *probeObjects
	filters    []*netlink.BpfFilter
}

func setRlimit() error {
	log.Printf("Setting rlimit - soft: %v | hard: %v\n", tenMegaBytes, twentyMegaBytes)

	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: tenMegaBytes,
		Max: twentyMegaBytes,
	})
}

func (p *probe) loadObjects() error {
	log.Printf("Loading probe object into kernel")

	objs := probeObjects{}

	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) createQdisc() error {
	log.Printf("Creating clsact qdisc")

	p.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	if err := p.handle.QdiscAdd(p.qdisc); err != nil {
		if err := p.handle.QdiscReplace(p.qdisc); err != nil {
			return err
		}
	}

	return nil
}

func (p *probe) createFilters() error {
	log.Printf("Creating qdisc ingress/egress filters")

	addFilter := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			Fd:           p.bpfObjects.probePrograms.Flat.FD(),
			DirectAction: true,
		})
	}

	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	for _, filter := range p.filters {
		if err := p.handle.FilterAdd(filter); err != nil {
			if err := p.handle.FilterReplace(filter); err != nil {
				return err
			}
		}
	}

	return nil
}

func newProbe(iface netlink.Link) (*probe, error) {
	log.Println("Creating a new probe")

	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)

	if err != nil {
		log.Printf("Failed getting netlink handle: %v", err)
		return nil, err
	}

	prbe := probe{
		iface:  iface,
		handle: handle,
	}

	if err := prbe.loadObjects(); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		prbe.Close()
		return nil, err
	}

	if err := prbe.createQdisc(); err != nil {
		log.Printf("Failed creating qdisc: %v", err)
		prbe.Close()
		return nil, err
	}

	if err := prbe.createFilters(); err != nil {
		log.Printf("Failed creating qdisc filters: %v", err)
		prbe.Close()
		return nil, err
	}

	return &prbe, nil
}

// Close removes whatever the probe has set up so far.
// It keeps going on errors so a partially created probe is still cleaned up.
func (p *probe) Close() error {
	var firstErr error

	if p.qdisc != nil {
		log.Println("Removing qdisc")
		if err := p.handle.QdiscDel(p.qdisc); err != nil {
			log.Printf("Failed deleting qdisc: %v", err)
			firstErr = err
		}
	}

	if p.bpfObjects != nil {
		log.Println("Closing eBPF object")
		if err := p.bpfObjects.Close(); err != nil {
			log.Printf("Failed closing eBPF object: %v", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	log.Println("Deleting handle")
	p.handle.Delete()

	return firstErr
}

// matchesFilter reports whether a packet matches the user's IP and port filters.
// A filter that is not set matches everything.
func matchesFilter(pkt packet.Packet, userInput types.UserInput) bool {
	if userInput.IP.IsValid() && userInput.IP != pkt.SrcIP.Unmap() && userInput.IP != pkt.DstIP.Unmap() {
		return false
	}

	if userInput.Port != 0 && userInput.Port != pkt.SrcPort && userInput.Port != pkt.DstPort {
		return false
	}

	return true
}

// Run attaches the probe, reads from the eBPF map
// as well as calculating and displaying the flow latencies
func Run(ctx context.Context, userInput types.UserInput) error {
	log.Println("Starting up the probe")

	if err := setRlimit(); err != nil {
		log.Printf("Failed setting rlimit: %v", err)
		return err
	}

	flowtable := flowtable.NewFlowTable()

	go func() {
		for range flowtable.Ticker.C {
			flowtable.Prune()
		}
	}()

	probe, err := newProbe(userInput.Interface)

	if err != nil {
		return err
	}

	pipe := probe.bpfObjects.probeMaps.Pipe

	reader, err := ringbuf.NewReader(pipe)
	if err != nil {
		log.Printf("Failed opening ringbuf reader: %v", err)
		probe.Close()
		return err
	}
	defer reader.Close()

	eventChan := make(chan []byte)

	go func() {
		for {
			event, err := reader.Read()
			if err != nil {
				log.Printf("Failed reading from ringbuf: %v", err)
				return
			}

			eventChan <- event.RawSample
		}
	}()

	for {
		select {
		case <-ctx.Done():
			flowtable.Ticker.Stop()
			return probe.Close()

		case pkt := <-eventChan:
			packetAttrs, ok := packet.UnmarshalBinary(pkt)
			if !ok {
				log.Printf("Could not unmarshall packet: %+v", pkt)
				continue
			}

			if matchesFilter(packetAttrs, userInput) {
				packet.CalcLatency(packetAttrs, flowtable)
			}
		}
	}
}
