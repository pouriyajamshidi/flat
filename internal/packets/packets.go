package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func EthernetHeader(proto layers.EthernetType) []byte {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{5, 4, 3, 2, 1, 0},
		EthernetType: proto,
	}

	if err := eth.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		panic(err)
	}

	return buf.Bytes()[0:14] // Override the gopacket padding. If not done like this, it will pad it to make a 60 byte ethernet frame
}

func IPv4Header(proto layers.IPProtocol) []byte {
	buf := gopacket.NewSerializeBuffer()

	ip := &layers.IPv4{
		SrcIP:    net.IP{1, 1, 1, 1},
		DstIP:    net.IP{2, 2, 2, 2},
		Protocol: proto,
	}

	if err := ip.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func TCPv4SYN() []byte {
	var packet []byte
	packet = append(packet, EthernetHeader(layers.EthernetTypeIPv4)...)
	packet = append(packet, IPv4Header(layers.IPProtocolTCP)...)

	buf := gopacket.NewSerializeBuffer()

	tcp := &layers.TCP{
		SrcPort: 123,
		DstPort: 456,
		SYN:     true,
	}

	if err := tcp.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		panic(err)
	}

	fmt.Println(buf.Bytes())

	return append(packet, buf.Bytes()...)
}

func TCPv4ACK() []byte {
	var packet []byte
	packet = append(packet, EthernetHeader(layers.EthernetTypeIPv4)...)
	packet = append(packet, IPv4Header(layers.IPProtocolTCP)...)

	buf := gopacket.NewSerializeBuffer()

	tcp := &layers.TCP{
		SrcPort: 123,
		DstPort: 456,
		ACK:     true,
	}

	if err := tcp.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		panic(err)
	}

	fmt.Println(buf.Bytes())

	return append(packet, buf.Bytes()...)
}

func TCPv4SYNACK() []byte {
	var packet []byte
	packet = append(packet, EthernetHeader(layers.EthernetTypeIPv4)...)
	packet = append(packet, IPv4Header(layers.IPProtocolTCP)...)
	buf := gopacket.NewSerializeBuffer()

	tcp := &layers.TCP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   123,
		DstPort:   456,
		SYN:       true,
		ACK:       true,
	}

	if err := tcp.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		panic(err)
	}

	fmt.Println(buf.Bytes())

	return append(packet, buf.Bytes()...)
}
