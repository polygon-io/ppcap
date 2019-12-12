

package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sync"
	//
	"github.com/polygon-io/ppcap"
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
	log.Println("Starting Broadcaster..")
	flag.Parse()

	var ds = LoadDataStream(*file);
	
	if (ds == nil) {
		log.Fatal("Failed LoadDataStream");
		return;
	}
	
	var oChan = ReadDataStream(ds)
	
	SendToUDP(*addr, oChan);
	
	var wg sync.WaitGroup;
	wg.Add(1);
	wg.Wait();
}

func LoadDataStream(absPPCAPFilePath string) *ppcap.DataReadStream {
	log.Println("Reading in PPCAP File:", absPPCAPFilePath)
	
	var hdrlay ppcap.PacketHeaderLayout
	ppcap.BuildPacketHeaderLayout(&hdrlay, 0)
	
	dataFd, err := os.Open(absPPCAPFilePath);
	
	if err != nil {
		return nil;
	}
	
	return ppcap.NewDataReadStream(dataFd, &hdrlay);
}

func ReadDataStream(ds *ppcap.DataReadStream) chan([]byte) {
	
	var oChan = make(chan([]byte), 8192);
	
	go func(){
		
		var packet ppcap.NextPacketOutput;
		
		for {
			err := ds.ReadNextPacket( &packet )
			if err != nil {
				if err == io.EOF {
					// done
					break
				}
				log.Fatal( err )
			}
			
			var oBuff = make([]byte, packet.PayloadSize);
			
			copy(oBuff[0:packet.PayloadSize], packet.Payload[0:packet.PayloadSize]);
			
			oChan <- oBuff
		}
		
		close(oChan);
	}()
	
	return oChan;
}

func SendToUDP(udpAddressString string, packets chan([]byte)) {
	
	udpAddr, err := net.ResolveUDPAddr("udp", udpAddressString);
	if err != nil {
		log.Fatal( err )
	}
	
	if !udpAddr.IP.IsMulticast() {
		log.Fatal("Address must be a multicast address")
	}
	
	// Open UDP Connection:
	conn, err := net.ListenPacket("udp", udpAddressString);
	
	if err != nil {
		log.Fatal( err )
	}
	
	// Start writing to the network:
	log.Println("UDP Connection Opened")
	
	go func() {
		
		for cPacket := range(packets) {
			_, err := conn.WriteTo(cPacket, udpAddr);
			
			if err != nil {
				log.Println("WriteTo Error:", err);
				break;
			}
			
		}
		
	}()
}



