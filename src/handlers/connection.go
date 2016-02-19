package handlers

import (
	"fmt"
	"sync"

	"github.com/gorilla/websocket"
)

type conn struct {
	ws     *websocket.Conn
	userID string
	send   chan *Message
	h      *hub
}

func (c *conn) write(wg *sync.WaitGroup) error {
	defer func() {
		c.ws.Close()
		wg.Done()
	}()
	//c.ws.SetWriteDeadline(time.Now().Add(writeWait))

	for {
		select {
		case msg, ok := <-c.send:
			if !ok {
				return nil
			}
			if err := c.ws.WriteJSON(msg); err != nil {
				return err
			}
		}
	}
}

func (c *conn) read(wg *sync.WaitGroup) error {
	defer func() {
		c.h.unregister <- c
		c.ws.Close()
		wg.Done()
	}()

	//c.ws.SetReadDeadline(time.Now().Add(pongWait))

	for {
		var (
			p   []byte
			err error
		)
		if _, p, err = c.ws.ReadMessage(); err != nil {
			fmt.Errorf("socket error:%v", err)
			break
		}
		id := string(p)
		if c.userID != "" {

			total := db.save(id, c.userID)
			msg := &Message{ID: id, Total: total}
			c.h.broadcast <- msg
		}
	}
	return nil
}

func initHub() *hub {
	return &hub{
		broadcast:   make(chan *Message),
		unregister:  make(chan *conn),
		register:    make(chan *conn),
		connections: make(map[*conn]bool),
	}
}

type hub struct {
	// registered connections
	connections map[*conn]bool
	// inbound messages
	broadcast chan *Message
	// register connections
	register chan *conn
	// unregister
	unregister chan *conn
}

func (h *hub) run() {
	for {
		select {
		case c := <-h.register:
			h.connections[c] = true
		case c := <-h.unregister:
			if _, ok := h.connections[c]; ok {
				delete(h.connections, c)
				close(c.send)
			}
		case m := <-h.broadcast:
			for c := range h.connections {
				select {
				case c.send <- m:
				default:
					close(c.send)
					delete(h.connections, c)
				}

			}
		}
	}
}
