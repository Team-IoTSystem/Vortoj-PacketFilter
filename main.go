package main

import (
	"fmt"
	"log"
	"time"

	"./lifecycle"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "en0" //ifconfigやip aとかで調べて使ってください
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	// Will reuse these for each packet
	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	tcpLayer layers.TCP
)

func main() {
	// Open device pcap
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//packet analayzer
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}
		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}

		//パケットの解析をしていく
		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeTCP {

				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					lifecycle.InsertPacketData(&lifecycle.TPacket{
						DeviceID:  "NOT_DEVICEID",
						SrcMAC:    ethLayer.SrcMAC.String(),
						DstMAC:    ethLayer.DstMAC.String(),
						SrcIP:     ipLayer.SrcIP.String(),
						DstIP:     ipLayer.DstIP.String(),
						SrcPort:   tcpLayer.SrcPort.String(),
						DstPort:   tcpLayer.DstPort.String(),
						SYN:       tcpLayer.SYN,
						ACK:       tcpLayer.ACK,
						Sequence:  int64(tcpLayer.Seq),
						Protocol:  string(ipLayer.Protocol.String()),
						Length:    int64(ipLayer.Length),
						DataChank: applicationLayer.Payload(),
					})
				}
			}

		}

	}
}
