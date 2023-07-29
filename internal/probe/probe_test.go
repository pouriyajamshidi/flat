package probe

import (
	"testing"

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
