package lifecycle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
)

func Unix_server(listener net.Listener, channel_packet chan TPacket) {
	for {
		fd, err := listener.Accept()
		if err != nil {
			break
		}
		log.Println("go process!")
		unix_process(fd, channel_packet)
	}
}

func unix_process(fd net.Conn, channel_packet chan TPacket) {
	for {
		// buf := make([]byte, 512)
		// nr, err := fd.Read(buf)
		// if err != nil {
		// 	break
		// ]
		ch_temp := <-channel_packet
		buff := &bytes.Buffer{}
		json.NewEncoder(buff).Encode(ch_temp)
		//err := binary.Write(buff, binary.BigEndian, ch_temp)

		fmt.Printf("Recieved: %v", buff.Bytes())

		_, err := fd.Write(buff.Bytes())
		if err != nil {
			log.Printf("error: %v\n", err)
			break
		}
	}
}

// func toStringPacket()
