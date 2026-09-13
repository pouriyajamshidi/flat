package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/pouriyajamshidi/flat/internal/probe"
	"github.com/pouriyajamshidi/flat/internal/types"
	"github.com/vishvananda/netlink"
)

// displayInterfaces displays all available network interfaces
func displayInterfaces() {
	interfaces, err := net.Interfaces()

	if err != nil {
		log.Fatalf("Failed fetching network interfaces: %v", err)
	}

	for i, iface := range interfaces {
		fmt.Printf("%d) %s\n", i, iface.Name)
	}
	os.Exit(1)
}

// getUserInput gets and validates user input
func getUserInput() types.UserInput {
	ifaceFlag := flag.String("i", "eth0", "interface to attach the probe to")
	ipFlag := flag.String("ip", "", "IP address to track (optional)")
	portFlag := flag.Uint("port", 0, "Port number to track (optional)")

	flag.Parse()

	iface, err := netlink.LinkByName(*ifaceFlag)

	if err != nil {
		log.Printf("Could not find interface %v: %v", *ifaceFlag, err)
		displayInterfaces()
	}

	var userInput types.UserInput

	userInput.Interface = iface

	if *ipFlag != "" {
		userInput.IP, err = netip.ParseAddr(*ipFlag)

		if err != nil {
			log.Printf("Could not parse IP address %v: %v", *ipFlag, err)
			os.Exit(1)
		}

		log.Printf("Filtering results on IP %v", userInput.IP)
	}

	if *portFlag != 0 {
		if *portFlag > 65535 {
			log.Printf("Invalid port %v: must be between 1 and 65535", *portFlag)
			os.Exit(1)
		}

		userInput.Port = uint16(*portFlag)

		log.Printf("Filtering results on port %d", userInput.Port)
	}

	return userInput
}

func main() {
	userInput := getUserInput()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// After the first signal, restore the default behavior
	// so a second Ctrl+C exits right away if the cleanup hangs
	context.AfterFunc(ctx, stop)

	if err := probe.Run(ctx, userInput); err != nil {
		log.Fatalf("Failed running flat: %v", err)
	}
}
