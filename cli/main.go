

package main

import (
	"io"
	"os"
	"fmt"
	"log"
	"net"
	"flag"
	ppcap "github.com/polygon-io/ppcap"
)

// CLI Params:
var file = flag.String("f", "", "Read in a PCAP file")
var addr = flag.String("a", "", "Multicast address to broadcast to")



/*

	PPCAPD ClI TOOL

		This is the start of the CLI, with the ability to broadcast 
		a ppcapd file to a multicast address on the network.

		Need to use something like Cobra CLI to make it 
		much more powerful / useful


	Example CLI Call:
	go run *.go -f ~/nyse-imbalances/nyse-imbalance-net-a-2019-02-20.ppcapd -a 233.125.89.36:11106


 */

func main(){
	fmt.Println("Starting Broadcaster..")
	flag.Parse()
	packets, err := loadPpcapFile( *file ); if err != nil {
		log.Fatal( err )
	}
	err = sendToUDP( *addr, packets ); if err != nil {
		log.Fatal( err )
	}
}



func sendToUDP( address string, packets chan ppcap.NextPacketOutput ) error {

	// Make sure it's a UDP Multicast Address:
	udpAddr, err := net.ResolveUDPAddr("udp", address); if err != nil {
		log.Fatal( err )
	}
	if !udpAddr.IP.IsMulticast() {
		log.Fatal("Address must be a multicast address")
	}

	// Open UDP Connection:
	conn, err := net.ListenPacket("udp", address); if err != nil {
		log.Fatal( err )
	}
	defer conn.Close()

	// Start writing to the network:
	fmt.Println("UDP Connection Opened")
	for {
		pkt := <- packets
		_, err := conn.WriteTo(pkt.Payload, udpAddr); if err != nil {
			return err
		}
	}
}



func loadPpcapFile( filename string ) ( chan ppcap.NextPacketOutput, error ) {
	fmt.Println("Reading in PPCAPD File:", filename)
	packets := make( chan ppcap.NextPacketOutput )

	var hdrlay ppcap.PacketHeaderLayout
	ppcap.BuildPacketHeaderLayout( &hdrlay, 0 )

	dataFd, err := os.Open( filename ); if err != nil {
		return packets, err
	}
	reader := ppcap.NewDataReadStream( dataFd, &hdrlay )
	var packet ppcap.NextPacketOutput

	go func(){
		for {
			err := reader.ReadNextPacket( &packet )
			if err != nil {
				if err == io.EOF {
					// done
					break
				}
				log.Fatal( err )
			}
			packets <- packet
		}
		close( packets )
	}()

	return packets, nil
}

