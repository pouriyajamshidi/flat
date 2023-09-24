package clsact

import "github.com/vishvananda/netlink"

// ClsAct represents a CLSAct netlink qdisc
type ClsAct struct {
	attrs *netlink.QdiscAttrs
}

// NewClsAct creates a new ClsAct struct
func NewClsAct(attrs *netlink.QdiscAttrs) *ClsAct {
	return &ClsAct{attrs: attrs}
}

// Attrs returns netlink.QdiscAttrs. Satisfies the Qdisc interface
func (qdisc *ClsAct) Attrs() *netlink.QdiscAttrs {
	return qdisc.attrs
}

// Type returns the qdisc type. Satisfies the Qdisc interface
func (qdisc *ClsAct) Type() string {
	return "clsact"
}
