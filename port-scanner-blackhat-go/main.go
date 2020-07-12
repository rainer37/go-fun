package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	snaplen = int32(1600)
	promisc = false
	timeout = pcap.BlockForever
	filter = "tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] == 0x18"
	devFound = false
	results map[string]int

	iface *string
	targetAddr *string
	ports *string
)

func init() {
	iface = flag.String("iface", "eth0", "interface of your target device")
	targetAddr = flag.String("target", "", "target ip address")
	ports = flag.String("ports", "80,53", "ports to scan")
	flag.Parse()
	checkLocalDevice()
	results = make(map[string]int)
	log.Infof("Scanning %s on ports %v", *targetAddr, *ports)
}

func checkLocalDevice() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Error(err.Error())
	}
	for _, device := range devices {
		if len(device.Addresses) < 1 {
			continue
		}
		for _, addr := range device.Addresses {
			if !addr.IP.IsLoopback() && addr.IP.To4() != nil && device.Name == *iface{
				log.Infof("Found a device %s => %s", device.Name, addr.IP)
			}
		}
	}
}

func capture(iface, target string) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		log.Panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Panic(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Info("starting capture packets, link type: ", handle.LinkType())

	// polling on the chan of packets from Packets()
	for packet := range source.Packets() {
		// log.Info("got a packet ", packet.String())
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue
		}

		srcHost := networkLayer.NetworkFlow().Src().String()
		srcPort := transportLayer.TransportFlow().Src().String()

		if srcHost != target {
			continue
		}
		results[srcPort]++ // found a bad port
	}
}

func main() {
	go capture(*iface, *targetAddr) // start to capturing packets
	time.Sleep(3 * time.Second)

	ports := strings.Split(*ports, ",")
	if len(ports) < 1 {
		log.Error("needs comma separated list or ports")
	}

	for _, port := range ports {
		target := fmt.Sprintf("%s:%s", *targetAddr, port)
		log.Info("Trying ", target)
		c, err := net.DialTimeout("tcp", target, 2000 * time.Millisecond)
		if err != nil {
			log.Error(err)
			continue
		}
		c.Close()
	}
	time.Sleep(2 * time.Second)

	for port, confidence := range results {
		if confidence >= 1 {
			log.Infof("Port %s open (confidence: %d)", port, confidence)
		}
	}
}