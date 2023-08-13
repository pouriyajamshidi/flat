package packet

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"net/netip"

	"github.com/pouriyajamshidi/flat/internal/flowtable"
)

/*

Remember that net.IP is just a []byte

The To4() converts it to the 4-byte representation

Example for net.Parse(192.168.1.1):

Original:  net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x1, 0x1}
After To4: net.IP{0xc0, 0xa8, 0x1, 0x1}

*/

const (
	udp = "UDP"
	tcp = "TCP"
)

type Packet struct {
	SrcIP     netip.Addr
	DstIP     netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Syn       bool
	Ack       bool
	Ttl       uint8
	TimeStamp uint64
}

func hash(value []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(value)
	return hash.Sum64()
}

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

func UnmarshalBinary(in []byte) (Packet, bool) {
	srcIP, ok := netip.AddrFromSlice(in[0:16])

	if !ok {
		return Packet{}, ok
	}

	dstIP, ok := netip.AddrFromSlice(in[16:32])

	if !ok {
		return Packet{}, ok
	}

	srcPort := binary.BigEndian.Uint16(in[32:34])
	dstPort := binary.BigEndian.Uint16(in[34:36])

	// Offset of 2 bytes as packet_t struct is 64-bit aligned.
	timeStamp := binary.LittleEndian.Uint64(in[41:49])

	return Packet{
		SrcIP:     srcIP,
		SrcPort:   uint16(srcPort),
		DstIP:     dstIP,
		DstPort:   uint16(dstPort),
		Protocol:  in[36],
		Syn:       in[37] == 1,
		Ack:       in[38] == 1,
		Ttl:       in[39],
		TimeStamp: timeStamp,
	}, true
}

var ipProtoNums = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

func CalcLatency(pkt Packet, table *flowtable.FlowTable) {
	proto, ok := ipProtoNums[pkt.Protocol]

	if !ok {
		log.Print("Failed fetching protocol number")
		return
	}

	pktHash := pkt.Hash()

	ts, ok := table.Get(pktHash)

	if !ok && pkt.Syn {
		table.Insert(pktHash, pkt.TimeStamp)
		return
	} else if !ok && proto == udp {
		table.Insert(pktHash, pkt.TimeStamp)
		return
	}

	convertIPToString := func(address netip.Addr) string {
		return address.Unmap().String()
	}

	if (ok && pkt.Ack) || (ok && proto == udp) {
		// fmt.Printf("(%v) Flow | src: %v:%v dst: %v:%v TTL: %v \tlatency: %.3f ms\n", // nice format
		fmt.Printf("(%v) Flow | src: %v:%v | dst: %v:%v | TTL: %v |\tlatency: %.3f ms\n",
			proto,
			convertIPToString(pkt.DstIP),
			pkt.DstPort,
			convertIPToString(pkt.SrcIP),
			pkt.SrcPort,
			pkt.Ttl,
			(float64(pkt.TimeStamp)-float64(ts))/1000000,
		)

		table.Remove(pktHash)
	}
}
