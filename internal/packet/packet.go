package packet

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/netip"

	"github.com/pouriyajamshidi/flat/internal/nixtime"
)

/*

Remember that net.IP is just a []byte

The To4() converts it to the 4-byte representation

Example for net.Parse(192.168.1.1):

Original:  net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x1, 0x1}
After To4: net.IP{0xc0, 0xa8, 0x1, 0x1}

*/

type Packet struct {
	SrcIP     netip.Addr
	DstIP     netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Syn       bool
	Ack       bool
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
	timeStamp := binary.LittleEndian.Uint64(in[40:48])

	return Packet{
		SrcIP:     srcIP,
		SrcPort:   uint16(srcPort),
		DstIP:     dstIP,
		DstPort:   uint16(dstPort),
		Protocol:  in[36],
		Syn:       in[37] == 1,
		Ack:       in[38] == 1,
		TimeStamp: timeStamp,
	}, true
}

var ipProtoNums = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

func PruneFlowTable(table map[uint64]uint64) {
	now := nixtime.GetNanosecSinceBoot()

	for hash, timestamp := range table {
		if (now-timestamp)/1000000 > 10000 {
			fmt.Printf("Removing stale entry from flowtable: %v", hash)
			delete(table, hash)
		}
	}
}

var flowTable = make(map[uint64]uint64)

func CalcLatency(pkt Packet) {
	pktHash := pkt.Hash()

	ts, ok := flowTable[pktHash]

	if !ok && pkt.Syn {
		flowTable[pktHash] = pkt.TimeStamp
		return
	} else if !ok && pkt.Protocol == 17 {
		flowTable[pktHash] = pkt.TimeStamp
		return
	}

	proto, _ := ipProtoNums[pkt.Protocol]

	convertIPToString := func(address netip.Addr) string {
		return address.Unmap().String()
	}

	if (ok && pkt.Ack) || (ok && proto == "UDP") {
		fmt.Printf("(%v) Flow latency from %v:%v to %v:%v -> %.3f ms\n",
			proto,
			convertIPToString(pkt.DstIP),
			pkt.DstPort,
			convertIPToString(pkt.SrcIP),
			pkt.SrcPort,
			(float64(pkt.TimeStamp)-float64(ts))/1000000,
		)

		delete(flowTable, pktHash)
	}

	PruneFlowTable(flowTable)
}
