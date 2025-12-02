package main

import (
	"log"
	"runtime"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	handleRead, err := pcap.OpenLive("enp1s0f0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handleRead.Close()

	handleWrite, err := pcap.OpenLive("enp1s0f1", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handleWrite.Close()

	packetChan := make(chan gopacket.Packet, 10000)
	writeChan := make(chan []byte, 10000)

	go func() {
		for data := range writeChan {
			handleWrite.WritePacketData(data)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for packet := range packetChan {
				drop := false
				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dns, _ := dnsLayer.(*layers.DNS)
					for _, q := range dns.Questions {
						if string(q.Name) == "1x2y3z.xyz" {
							drop = true
							break
						}
					}
				}

				if !drop {
					// fmt.Println(packet)
					writeChan <- packet.Data()
				}
			}
		}()
	}

	packetSource := gopacket.NewPacketSource(handleRead, handleRead.LinkType())
	packetSource.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	for packet := range packetSource.Packets() {
		packetChan <- packet
	}

	close(packetChan)
	wg.Wait()
	close(writeChan)
}
