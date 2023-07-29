package probe

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf/perf"
	"github.com/pouriyajamshidi/flat/clsact"
	"github.com/pouriyajamshidi/flat/internal/packet"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/flat.c - -O3  -Wall -Werror -Wno-address-of-packed-member

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	bpfObjects *probeObjects
	filters    []*netlink.BpfFilter
}

func (p *probe) loadObjects() error {
	objs := probeObjects{}

	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) createQdisc() error {
	p.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	if err := p.handle.QdiscAdd(p.qdisc); err != nil {
		return err
	}

	return nil
}

func (p *probe) createFilters() error {
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
		if err := p.handle.FilterReplace(filter); err != nil {
			return err
		}
	}

	return nil
}

func newProbe(iface netlink.Link) (*probe, error) {
	if err := setRlimit(); err != nil {
		return nil, err
	}

	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	prbe := probe{
		iface:  iface,
		handle: handle,
	}

	if err := prbe.loadObjects(); err != nil {
		return nil, err
	}

	if err := prbe.createQdisc(); err != nil {
		return nil, err
	}

	if err := prbe.createFilters(); err != nil {
		return nil, err
	}

	return &prbe, nil
}

func (p *probe) Close() error {
	if err := p.handle.QdiscDel(p.qdisc); err != nil {
		return err
	}

	for _, filter := range p.filters {
		if err := p.handle.FilterDel(filter); err != nil {
			return err
		}
	}

	if err := p.bpfObjects.Close(); err != nil {
		return err
	}

	p.handle.Delete()

	return nil
}

func Run(ctx context.Context, iface netlink.Link) error {
	probe, err := newProbe(iface)

	if err != nil {
		return err
	}

	pipe := probe.bpfObjects.probeMaps.Pipe

	rd, err := perf.NewReader(pipe, 10)

	if err != nil {
		return err
	}

	defer rd.Close()

	c := make(chan []byte)

	go func() {
		for {
			event, err := rd.Read()
			if err != nil {
				fmt.Println(err)
				return
			}
			c <- event.RawSample
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return probe.Close()
		case pkt := <-c:
			packetAttrs, ok := packet.UnmarshalBinary(pkt)
			if !ok {
				fmt.Println("Could not parse IP address")
			}
			packet.CalcLatency(packetAttrs)
		}
	}
}

func setRlimit() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: 1024 * 1024 * 10,
		Max: 1024 * 1024 * 10,
	})
}
