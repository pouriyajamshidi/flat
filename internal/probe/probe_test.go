package probe

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/pouriyajamshidi/flat/internal/packets"
	"github.com/stretchr/testify/require"
)

func TestTCPv4SYNPacket(t *testing.T) {
	prbe := probe{}
	err := prbe.loadObjects()
	require.NoError(t, err)

	in := packets.TCPv4SYN()
	res, out, err := prbe.bpfObjects.Flat.Test(in)

	require.NoError(t, err)
	require.Equal(t, uint32(0), res)
	require.Equal(t, in, out)
}

func TestTCPv4ACKPacket(t *testing.T) {
	prbe := probe{}
	err := prbe.loadObjects()
	require.NoError(t, err)

	in := packets.TCPv4ACK()
	res, out, err := prbe.bpfObjects.Flat.Test(in)

	require.NoError(t, err)
	require.Equal(t, uint32(0), res)
	require.Equal(t, in, out)
}

func TestTCPv4SYNACKPacket(t *testing.T) {
	prbe := probe{}
	err := prbe.loadObjects()
	require.NoError(t, err)

	in := packets.TCPv4SYNACK()
	res, out, err := prbe.bpfObjects.Flat.Test(in)

	require.NoError(t, err)
	require.Equal(t, uint32(0), res)
	require.Equal(t, in, out)
}

func TestDroppedPacketsWhenRingBufferIsFull(t *testing.T) {
	prbe := probe{}
	err := prbe.loadObjects()
	require.NoError(t, err)
	defer prbe.bpfObjects.Close()

	dropped, err := prbe.droppedPackets()
	require.NoError(t, err)
	require.Equal(t, uint64(0), dropped)

	// Nothing reads the ring buffer here, so it fills up after about 9000 SYN packets
	_, err = prbe.bpfObjects.Flat.Run(&ebpf.RunOptions{Data: packets.TCPv4SYN(), Repeat: 20_000})
	require.NoError(t, err)

	dropped, err = prbe.droppedPackets()
	require.NoError(t, err)
	require.Greater(t, dropped, uint64(0))
}
