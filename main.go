package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"./lifecycle"
	"./utility"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "en7" //ifconfigやip aとかで調べて使ってください
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

//const SOCK_ADDRESS = "/tmp/test.sock"

func main() {
	// Open device pcap
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	log.SetFlags(log.Lshortfile)
	log.Println("Starting echo server")

	//unix domain socket----
	//create tmp filename
	// tempdir, err := ioutil.TempDir("", "PacketFillter")
	// if err != nil {
	// 	log.Printf("error: %v\n", err)
	// 	panic(err)
	// }
	// pid := strconv.Itoa(os.Getpid())
	// SOCK_ADDRESS := tempdir + "/server" + pid
	// if err := os.Chmod(tempdir, 0700); err != nil {
	// 	log.Printf("error: %v\n", err)
	// 	panic(err)
	// }
	SOCK_ADDRESS := "/tmp/example.sock"
	//unix domain socket is Listen
	listener, err := net.Listen("unix", SOCK_ADDRESS)
	if err != nil {
		log.Fatal("Listen error: ", err)
		panic(err)
	}
	log.Println("Listen to unix domain")

	defer func(listener net.Listener) {
		listener.Close()
		if false == utility.Exists(SOCK_ADDRESS) {
			if err := os.Remove(SOCK_ADDRESS); err != nil {
				panic(err)
			}
		}
	}(listener)

	shutdown(listener)
	log.Println("shutdown seting")
	ch_packet := make(chan lifecycle.TPacket)
	go lifecycle.Unix_server(listener, ch_packet)
	//packet analayzer
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
		)
		found_layertypes := []gopacket.LayerType{}
		err := parser.DecodeLayers(packet.Data(), &found_layertypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}

		//パケットの解析をしていく
		for _, layertype := range found_layertypes {
			if layertype == layers.LayerTypeTCP {
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					struct_packetdata := lifecycle.TPacket{
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
					}
					log.Println("getpacket")
					//DomainSocket
					ch_packet <- struct_packetdata

					//InsertDB
					//DBはapplicationdataがある程度ある場合のみ
					if 10 < len(applicationLayer.Payload()) {
						lifecycle.InsertPacketData(&struct_packetdata)
					}
				}
			}

		}
	}
}

func shutdown(listener net.Listener) {
	signalCh := make(chan os.Signal, 2)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		s := <-signalCh
		if err := listener.Close(); err != nil {
			log.Printf("error: %v", err)
		}
		log.Print(s)
		os.Exit(1)
	}()
}
