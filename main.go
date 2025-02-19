//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"log"
	"time"
)

var (
	NIC          string
	QueueNum     int
	QueueID      int
	PcapFile     string
	Loop         bool
	debug        bool
	transmitChan = make(chan []byte, 1000000)
)

func main() {
	// step 1. Parse command-line flags
	initFlagParam()

	// step 2. Read pcap file and extract tcp frames
	frames := extractFrameFromPcap(transmitChan)
	fmt.Println("Extract frames from pcap file successfully.")

	// step 3. Initialize the XDP socket
	xsks, err := initXdpSocket()
	if err != nil {
		fmt.Println("Fail to initialize the XDP socket:", err)
		return
	}

	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()

	// step 4. Counter
	go count(xsks)

	// step 5. Transmit packets loop.
	for i := 0; i < len(frames) && Loop; i = (i + 1) % len(frames) {
		transmitChan <- frames[i]
	}
	fmt.Println("Finished sending packets.")
}

func initFlagParam() {
	flag.StringVar(&NIC, "nic", "eno2", "Network interface to attach to.")
	flag.IntVar(&QueueNum, "queueNum", 1, "The amount of queue on the network interface to attach to.")
	flag.IntVar(&QueueID, "queueId", 0, "The id of queue.")
	flag.StringVar(&PcapFile, "pcap", "tcp_packets.pcap", "Path to the pcap file containing TCP packets.")
	flag.BoolVar(&Loop, "loop", true, "Enable replay pcap loop.")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode.")
	flag.Parse()
	fmt.Printf("nic: %v, loop: %v, debug: %v\n", NIC, Loop, debug)
}

func initXdpSocket() ([]*xdp.Socket, error) {
	link, err := netlink.LinkByName(NIC)
	if err != nil {
		return nil, err
	}

	// 创建XDP程序（使用默认ebpf程序），无自定义内核代码
	program, err := xdp.NewProgram(QueueNum)
	if err != nil {
		return nil, err
	}
	defer program.Close()

	// 附加到网络接口
	if err = program.Attach(link.Attrs().Index); err != nil {
		return nil, err
	}
	defer program.Detach(link.Attrs().Index)

	xsks := make([]*xdp.Socket, QueueNum)
	for i := 0; i < len(xsks); i++ {
		if xsks[i], err = xdp.NewSocket(link.Attrs().Index, QueueID, nil); err != nil {
			return nil, err
		}
		defer xsks[i].Close()
		idx := i
		go transmit(xsks[idx])
	}
	return xsks, nil
}

func extractFrameFromPcap(transmitChan chan []byte) [][]byte {
	// Open pcap file
	handle, err := pcap.OpenOffline(PcapFile)
	if err != nil {
		panic(fmt.Sprintf("Failed to open pcap file: %v", err))
	}
	defer handle.Close()

	// Read packets from pcap file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	var frames [][]byte
	for packet := range packets {
		// Check if the packet is a TCP packet
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue // Skip non-TCP packets
		}

		// Serialize the entire Ethernet frame
		buf := gopacket.NewSerializeBuffer()
		err := gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, packet)
		if err != nil {
			log.Printf("Failed to serialize packet: %v", err)
			continue
		}
		frames = append(frames, buf.Bytes())

		transmitChan <- buf.Bytes()
	}
	return frames
}

func transmit(xsk *xdp.Socket) {
	pos := 0
	batch := 64
	packets := make([][]byte, batch)
	for {
		if pos < batch {
			packets[pos] = <-transmitChan
			pos++
			continue
		}
		descs := xsk.GetDescs(batch, false)
		if len(descs) == 0 {
			xsk.Poll(-1)
			if debug {
				fmt.Println("no free slots")
			}
			continue
		}

		frameLen := 0
		for j := 0; j < len(descs); j++ {
			frameLen = copy(xsk.GetFrame(descs[j]), packets[j])
			descs[j].Len = uint32(frameLen)
		}
		xsk.Transmit(descs)
		if _, _, err := xsk.Poll(-1); err != nil {
			if debug {
				fmt.Println("fail to poll:", err)
			}
			continue
		}

		for i := 0; i < len(descs) && i+len(descs) < batch; i++ {
			packets[i] = packets[i+len(descs)]
		}
		pos = batch - len(descs)
	}
}

func count(xsks []*xdp.Socket) {
	prev := make([]xdp.Stats, len(xsks))
	cur := make([]xdp.Stats, len(xsks))
	nums := make([]uint64, len(xsks))
	var total uint64
	for {
		time.Sleep(5 * time.Second)
		total = 0
		var err error
		for i := 0; i < len(xsks); i++ {
			cur[i], err = xsks[i].Stats()
			if err != nil {
				log.Printf("Failed to get stats: %v", err)
				continue
			}
			nums[i] = cur[i].Completed - prev[i].Completed
			prev[i] = cur[i]
			total += nums[i]
		}
		fmt.Printf("%d packets in 5s, transmit channel length: %d.\n", total, len(transmitChan))
	}
}
