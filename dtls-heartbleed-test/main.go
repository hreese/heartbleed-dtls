package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	_ "time"
)

type packet struct {
	listenerID uint64
	raddr      net.UDPAddr
	data       []byte
}

func Connection2Key(p *packet) string {
	return fmt.Sprintf("%x|%s", p.listenerID, p.raddr.String())
}

type UDPConnectionHandler interface {
	Handle(chan net.UDPConn, chan int)
}

func EchoTestHandler(outConn *net.UDPConn, packetChan chan *packet, closeChan chan string, key string) {
	pCounter := 0

	for {
		select {
		case p := <-packetChan:
			if pCounter < 3 {
				pCounter += 1
				// echo
				log.Printf("Sending echo reply to %+v\n", p.raddr)
				_, err := outConn.WriteToUDP(p.data, &p.raddr)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				log.Printf("Reached counter for %+v, quitting!\n", p.raddr)
				closeChan <- key
				return
			}
		}
	}
}

type handler struct {
	handlerMap     map[string]chan *packet
	accessChan     chan string
	amMutex        sync.Mutex
	nextHandlerIdx uint64
}

func (h *handler) Init() {
	h.handlerMap = make(map[string]chan *packet)
	h.accessChan = make(chan string)

	// this goroutine waits for channel closing requests and removes the
	// corresponding channel from h.handlerMap
	go func() {
		for {
			select {
			case closeMe := <-h.accessChan:
				h.amMutex.Lock()
				// XXX are we leaking channels here?
				//close(h.handlerMap[closeMe])
				delete(h.handlerMap, closeMe)
				h.amMutex.Unlock()
			}
		}
	}()
}

// Dispatch packet to proper goroutine or start a new one if needed
func (h *handler) Handle(c *net.UDPConn, p *packet) {
	key := Connection2Key(p)

	h.amMutex.Lock()
	handlerChan := h.handlerMap[key]
	if handlerChan == nil {
		log.Print("No handler found, creating new one")
		handlerChan = make(chan *packet, 16)
		h.handlerMap[key] = handlerChan
		// TODO start new connection handler here
		go EchoTestHandler(c, handlerChan, h.accessChan, key)
	}
	h.amMutex.Unlock()
	handlerChan <- p
}

func main() {
	var h handler
	h.Init()
	inChan := make(chan packet, 1024)

	// open listening socket on all addresses, random port
	inConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		log.Fatal(err)
	}

	// run listener as goroutine
	go func() {
		listenAddr := inConn.LocalAddr()
		localHost, localPort, _ := net.SplitHostPort(listenAddr.String())
		log.Printf("Listening on: %s %s\n", localHost, localPort)
		for {
			data := make([]byte, 65507)
			len, raddr, err := inConn.ReadFromUDP(data)
			if err != nil {
				log.Fatal(err)
			}
			inChan <- packet{listenerID: 4, raddr: *raddr, data: data[:len]}
			log.Print("New packet received.")
		}
	}()

	for {
		select {
		case inData := <-inChan:
			h.Handle(inConn, &inData)
		}
	}
}
