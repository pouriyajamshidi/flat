package clsact

import "github.com/vishvananda/netlink"

type ClsAct struct {
	attrs *netlink.QdiscAttrs
}

func NewClsAct(attrs *netlink.QdiscAttrs) *ClsAct {
	return &ClsAct{attrs: attrs}
}

func (qdisc *ClsAct) Attrs() *netlink.QdiscAttrs {
	return qdisc.attrs
}

func (qdisc *ClsAct) Type() string {
	return "clsact"
}
