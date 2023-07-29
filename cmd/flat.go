package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/pouriyajamshidi/flat/internal/probe"
	"github.com/vishvananda/netlink"
)

// signalHandler catches SIGINT and SIGTERM then exits the program
func signalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nCaught SIGINT... Exiting")
		cancel()
	}()
}

// displayInterfaces displays all available network interfaces
func displayInterfaces() {
	interfaces, err := net.Interfaces()

	if err != nil {
		log.Fatal("Failed fetching network interfaces")
		return
	}

	for i, iface := range interfaces {
		fmt.Printf("%d) %s\n", i, iface.Name)
	}
}

func main() {
	ifaceFlag := flag.String("interface", "wlp3s0", "interface to attach the probe to") // TODO: change default value to eth0
	flag.Parse()

	iface, err := netlink.LinkByName(*ifaceFlag)

	if err != nil {
		log.Printf("Could not find interface %v: %v", *ifaceFlag, err)

		displayInterfaces()

		os.Exit(1)
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalHandler(cancel)

	if err := probe.Run(ctx, iface); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
		os.Exit(1)
	}
}
