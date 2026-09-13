package packet

import (
	"net/netip"
	"testing"

	"github.com/pouriyajamshidi/flat/internal/flowtable"
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

func TestRetransmittedSYNRestartsMeasurement(t *testing.T) {
	table := flowtable.NewFlowTable()
	defer table.Ticker.Stop()

	syn := Packet{
		SrcIP:     netip.MustParseAddr("192.168.0.156"),
		DstIP:     netip.MustParseAddr("1.1.1.1"),
		SrcPort:   53264,
		DstPort:   443,
		Protocol:  6,
		Syn:       true,
		TimeStamp: 1_000,
	}

	CalcLatency(syn, table)

	syn.TimeStamp = 2_000
	CalcLatency(syn, table)

	ts, ok := table.Get(syn.Hash())
	require.True(t, ok)
	require.Equal(t, uint64(2_000), ts)

	synAck := Packet{
		SrcIP:     syn.DstIP,
		DstIP:     syn.SrcIP,
		SrcPort:   syn.DstPort,
		DstPort:   syn.SrcPort,
		Protocol:  6,
		Syn:       true,
		Ack:       true,
		TimeStamp: 2_500,
	}

	CalcLatency(synAck, table)

	_, ok = table.Get(syn.Hash())
	require.False(t, ok)
}
