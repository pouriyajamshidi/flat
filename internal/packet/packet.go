package packet

import (
	"encoding/binary"
	"hash/fnv"
	"log"
	"net/netip"

	"github.com/gookit/color"
	"github.com/pouriyajamshidi/flat/internal/flowtable"
)

var (
	colorLightYellow = color.LightYellow.Printf
	colorCyan        = color.Cyan.Printf
)

// Packet represents a TCP or UDP packet
type Packet struct {
	SrcIP     netip.Addr
	DstIP     netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	TTL       uint8
	Syn       bool
	Ack       bool
	TimeStamp uint64
}

func hash(value []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(value)
	return hash.Sum64()
}

// Hash hashes the packets based on their 5-tuple hash
func (pkt *Packet) Hash() uint64 {
	tmp := make([]byte, 2)

	var src []byte
	var dst []byte
	var proto []byte

	binary.BigEndian.PutUint16(tmp, pkt.SrcPort)
	src = append(pkt.SrcIP.AsSlice(), tmp...)

	binary.BigEndian.PutUint16(tmp, pkt.DstPort)
	dst = append(pkt.DstIP.AsSlice(), tmp...)

	binary.BigEndian.PutUint16(tmp, uint16(pkt.Protocol))
	proto = append(proto, tmp...)

	return hash(src) + hash(dst) + hash(proto)
}

// UnmarshalBinary builds and fills up the Packet struct coming from eBPF map
func UnmarshalBinary(in []byte) (Packet, bool) {
	srcIP, ok := netip.AddrFromSlice(in[0:16])

	if !ok {
		return Packet{}, ok
	}

	dstIP, ok := netip.AddrFromSlice(in[16:32])

	if !ok {
		return Packet{}, ok
	}

	return Packet{
		SrcIP:     srcIP,
		SrcPort:   binary.BigEndian.Uint16(in[32:34]),
		DstIP:     dstIP,
		DstPort:   binary.BigEndian.Uint16(in[34:36]),
		Protocol:  in[36],
		TTL:       in[37],
		Syn:       in[38] == 1,
		Ack:       in[39] == 1,
		TimeStamp: binary.LittleEndian.Uint64(in[40:48]),
	}, true
}

var ipProtoNums = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

// CalcLatency calculates and displays flow latencies
func CalcLatency(pkt Packet, table *flowtable.FlowTable) {
	proto, ok := ipProtoNums[pkt.Protocol]

	if !ok {
		log.Print("Failed fetching protocol number: ", pkt.Protocol)
		return
	}

	pktHash := pkt.Hash()

	ts, ok := table.Get(pktHash)

	if !ok && pkt.Syn {
		table.Insert(pktHash, pkt.TimeStamp)
		return
	} else if !ok && proto == "UDP" {
		table.Insert(pktHash, pkt.TimeStamp)
		return
	} else if !ok {
		return
	}

	if pkt.Ack {
		colorCyan("(%v) | src: %v:%-7v\tdst: %v:%-9v\tTTL: %-4v\tlatency: %.3f ms\n",
			proto,
			pkt.DstIP.Unmap().String(),
			pkt.DstPort,
			pkt.SrcIP.Unmap().String(),
			pkt.SrcPort,
			pkt.TTL,
			(float64(pkt.TimeStamp)-float64(ts))/1000000,
		)
		table.Remove(pktHash)
	} else if proto == "UDP" {
		colorLightYellow("(%v) | src: %v:%-7v\tdst: %v:%-9v\tTTL: %-4v\tlatency: %.3f ms\n",
			proto,
			pkt.DstIP.Unmap().String(),
			pkt.DstPort,
			pkt.SrcIP.Unmap().String(),
			pkt.SrcPort,
			pkt.TTL,
			(float64(pkt.TimeStamp)-float64(ts))/1000000,
		)
		table.Remove(pktHash)
	}
}
