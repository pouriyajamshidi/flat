package types

import (
	"net/netip"

	"github.com/vishvananda/netlink"
)

// UserInput holds the information provided through flags
type UserInput struct {
	Interface netlink.Link
	IP        netip.Addr
	Port      uint16
}
