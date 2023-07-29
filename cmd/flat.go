package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/pouriyajamshidi/flat/internal/probe"
	"github.com/vishvananda/netlink"
)

func main() {
	ifaceFlag := flag.String("iface", "wlp3s0", "interface to attach the probe to")
	flag.Parse()

	iface, err := netlink.LinkByName(*ifaceFlag)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt)

	go func() {
		<-s
		fmt.Println("\nCaught SIGINT")
		signal.Stop(s)
		cancel()
	}()

	if err := probe.Run(ctx, iface); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
