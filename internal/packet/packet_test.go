package packet

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashReverseCollision(t *testing.T) {
	pakcetOutgoing := Packet{
		SrcIP:   netip.MustParseAddr("192.168.0.156"),
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		SrcPort: 53264,
		DstPort: 53,
	}
	pakcetIncoming := Packet{
		SrcIP:   netip.MustParseAddr("1.1.1.1"),
		DstIP:   netip.MustParseAddr("192.168.0.156"),
		SrcPort: 53,
		DstPort: 53264,
	}

	require.Equal(t, pakcetOutgoing.Hash(), pakcetIncoming.Hash())
}
