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
	filter = "tcp and src host %s && (tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] == 0x18)"
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

func scorePacket(packet gopacket.Packet) {
	srcPort := packet.TransportLayer().TransportFlow().Src().String()
	results[srcPort]++ // found a bad port
}

func capture(iface, target string, started chan<- struct{}, ScanInitDone <-chan struct{}, captureDone chan<- struct{}) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		log.Panic(err)
	}
	defer handle.Close()

	realFilter := fmt.Sprintf(filter, target)
	log.Info(realFilter)

	if err := handle.SetBPFFilter(realFilter); err != nil {
		log.Panic(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Debug("starting capture packets, link type: ", handle.LinkType())

	started <- struct{}{}
	close(started)

	// polling on the chan of packets from Packets()

LOOP:
	for {
		select {
		case <-ScanInitDone:
			log.Debug("Scan Init Done signal received")
			break LOOP
		case packet := <- source.Packets():
			scorePacket(packet)
		}
	}

	log.Info("Capture existed")
	captureDone <- struct{}{}
	close(captureDone)
}

func scanOne(port string, scanner chan<- struct{}) {
	defer func() {
		scanner <- struct {}{}
	}()

	target := fmt.Sprintf("%s:%s", *targetAddr, port)
	log.Infof("Trying %s", target)
	c, err := net.DialTimeout("tcp", target, 1000 * time.Millisecond)
	if err != nil {
		log.Debug(err)
		return
	}
	c.Close()
}

func scan(done chan<- struct{}, captureDone <-chan struct{}) {
	ports := strings.Split(*ports, ",")
	if len(ports) < 1 {
		log.Error("needs comma separated list or ports")
	}

	scanner := make(chan struct{}, len(ports))

	for _, port := range ports {
		go scanOne(port, scanner)
	}

	for range ports {
		<- scanner
	}

	done <- struct{}{}
	close(done)

	<- captureDone
	for port, confidence := range results {
		if confidence >= 1 {
			log.Infof("Port %s open (confidence: %d)", port, confidence)
		}
	}
}

func main() {
	stared := make(chan struct{})
	scanInitDone := make(chan struct{})
	captureDone := make(chan struct{})
	go capture(*iface, *targetAddr, stared, scanInitDone, captureDone) // start to capturing packets
	<- stared
	scan(scanInitDone, captureDone)
}