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
	os.Exit(1)
}

// getUserInput gets and validates user input
func getUserInput() types.UserInput {
	ifaceFlag := flag.String("i", "eth0", "interface to attach the probe to")
	ipFlag := flag.String("ip", "", "IP address to track (optional)")
	portFlag := flag.Uint("port", 0, "Port number to track (optional)")
	flag.Parse()

	var userInput types.UserInput

	iface, err := netlink.LinkByName(*ifaceFlag)

	if err != nil {
		log.Printf("Could not find interface %v: %v", *ifaceFlag, err)
		displayInterfaces()
	}

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
		if *portFlag < 1 || *portFlag > 65535 {
			log.Printf("Could not parse port %v: %v", *portFlag, err)
			os.Exit(1)
		}

		userInput.Port = uint16(*portFlag)

		log.Printf("Filtering results on port %d", userInput.Port)
	}

	return userInput
}

func main() {
	userInput := getUserInput()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalHandler(cancel)

	if err := probe.Run(ctx, userInput); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
	}
}
