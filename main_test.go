package main

import (
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	pcapFile = "jxjk.pcap" // pcap 文件路径
)

func TestMain12(t *testing.T) {
	// 1. 打开 pcap 文件
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return
	}
	defer handle.Close()

	// 2. 读取 pcap 文件中的数据包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 3. 提取帧
		// 提取以太网层
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			fmt.Printf("Ethernet Layer: %+v\n", ethernetPacket)

			// 提取 IP 层
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ipPacket, _ := ipLayer.(*layers.IPv4)
				fmt.Printf("IP Layer: %+v\n", ipPacket)

				// 提取 TCP 层
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcpPacket, _ := tcpLayer.(*layers.TCP)
					fmt.Printf("TCP Layer: %+v\n", tcpPacket)

					// 序列化各个层
					buf := gopacket.NewSerializeBuffer()
					_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, ethernetPacket, ipPacket, tcpPacket)

					fmt.Printf("=======\n%s\n+++++++\n%s\n#########\n", string(packet.Data()), string(buf.Bytes()))
				}
			}
		}
	}
}
