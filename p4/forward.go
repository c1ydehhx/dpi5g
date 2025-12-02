package main

import (
	domainfilter "dnsfilter/domainFilter"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func IsDNSBanned(queryDomain string) bool {
	if queryDomain == "x1y2z3.xyz" {
		return false
	} else {
		return true
	}
}

func main() {
	iface := "enp1s0f0"
	snaplen := int32(65535)
	promiscuous := true
	timeout := pcap.BlockForever

	handle, err := pcap.OpenLive(iface, snaplen, promiscuous, timeout)
	handle_export, _ := pcap.OpenLive("enp1s0f1", snaplen, false, timeout)

	if err != nil {
		log.Fatalf("Failed to open device %s: %v", iface, err)
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Printf("Listening on interface %s ...\n", iface)

	domainFilter := domainfilter.NewDomainFilter()
	err = domainFilter.LoadFile("ban.list")

	if err != nil {
		log.Fatalf("Failed to load block list: %v", err)
	}

	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)

		outIf, err := net.InterfaceByName("enp1s0f1")

		if err != nil {
			log.Fatalf("Failed to fetch network interface for export.")
		}

		if eth := packet.Layer(layers.LayerTypeEthernet); eth != nil {
			e := eth.(*layers.Ethernet)
			if e.SrcMAC.String() == outIf.HardwareAddr.String() {
				continue
			}
		}

		if dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			if !dns.QR {
				isValid := true

				for _, q := range dns.Questions {
					isValid = isValid && !domainFilter.Match(string(q.Name))

					// validString := "Valid"

					// if !isValid {
					// 	validString = "Invalid"
					// }

					// fmt.Printf("[%s] DNS Query Detected: %s (%s) -> Valid: %s\n", time.Now().Format("15:04:05.000"), string(q.Name), q.Type, validString)
				}
				if isValid {
					ethLayer := packet.Layer(layers.LayerTypeEthernet)

					if ethLayer == nil {
						log.Fatalf("Failed to fetch eth layer.")
						return
					}

					rawData := packet.Data()
					copy(rawData[6:12], outIf.HardwareAddr)

					handle_export.WritePacketData(rawData)
				}
			}
		}
	}
}
