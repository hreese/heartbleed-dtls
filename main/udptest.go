package main

import (
	"log"
	"net"
	_ "time"
)

type packet struct {
	localaddr net.UDPAddr
	data      []byte
}

func main() {
	inChan := make(chan packet, 1024)
	//outChan := make(chan packet, 1024)

	// address for random local port
	localaddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		log.Fatal(err)
	}

	// open listening socket
	in, err := net.ListenUDP("udp", localaddr)
	if err != nil {
		log.Fatal(err)
	}
	listenAddr := in.LocalAddr()
	localHost, localPort, _ := net.SplitHostPort(listenAddr.String())
	log.Printf("date | nc -u %s %s\n", localHost, localPort)

	// run listener as goroutine
	go func() {
		for {
			data := make([]byte, 9000)
			len, localaddr, err := in.ReadFromUDP(data)
			if err != nil {
				log.Fatal(err)
			}
			inChan <- packet{localaddr: *localaddr, data: data[:len]}
		}
	}()

	for {
		select {
		case inData := <-inChan:
			log.Printf("Received: %+v\n", inData)
			c, err := net.DialUDP("udp", localaddr, &inData.localaddr)
			if err != nil {
				log.Fatal(err)
			}
			//_, err = c.WriteToUDP(inData.data, &inData.addr)
			_, err = c.Write(inData.data)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Sent: %+v to %+v\n", inData.data, inData.localaddr)
		}
	}
}
