package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/JustinBeckwith/go-yelp/yelp"
	"github.com/dgrijalva/jwt-go"
	"github.com/rs/cors"

	"github.com/labstack/echo"
	mw "github.com/labstack/echo/middleware"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitter"
	"github.com/syntaqx/echo-middleware/session"
	"golang.org/x/net/websocket"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

const (
	privKeyPath = "keys/app.rsa"     // openssl genrsa -out app.rsa keysize
	pubKeyPath  = "keys/app.rsa.pub" // openssl rsa -in app.rsa -pubout > app.rsa.pub
)

// read the key files before starting http handlers
func init() {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	fatal(err)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// keeps track of visits in lieu of real database
type database struct {
	sync.RWMutex
	counter map[string]int
	visits  map[string]map[string]bool
}

func initDB() database {
	db := database{}
	db.counter = make(map[string]int)
	db.visits = make(map[string]map[string]bool)
	return db
}

func (db database) isGoing(barID, userID string) bool {
	if userID == "" {
		return false
	}
	isGoing := false
	db.RLock()
	if visits, ok := db.visits[userID]; ok {
		isGoing = visits[barID]
	}
	db.RUnlock()
	return isGoing
}

func (db database) getTotal(barID string) int {
	var total int
	db.RLock()
	total = db.counter[barID]
	db.RUnlock()
	return total
}

func (db database) save(barID string, userID string) int {

	db.Lock()
	total := 0

	// initialize user visits map
	if _, ok := db.visits[userID]; !ok {
		db.visits[userID] = make(map[string]bool)
	}

	// get current
	if current, ok := db.counter[barID]; ok {
		total = current
	}

	// if user has visited before, decrement by 1, and remove user from visits
	// otherwise increment by 1
	if _, ok := db.visits[userID][barID]; ok {
		total--
		delete(db.visits[userID], barID)
	} else {
		total++
		db.visits[userID][barID] = true
	}

	// update counter
	db.counter[barID] = total
	db.Unlock()
	return total
}

var db = initDB()

// Message is message broadcast to all connections
type Message struct {
	Total int    `json:"total"`
	ID    string `json:"id"` // yelp ID
}

// Bar is just a bar, man
type Bar struct {
	ID        string `json:"id"`
	Thumbnail string `json:"thumbnail"`
	Name      string `json:"name"`
	Review    string `json:"review"`
	Total     int    `json:"total"`
	Going     bool   `json:"going"`
}

type conn struct {
	ws     *websocket.Conn
	userID string
	send   chan *Message
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
			if err := websocket.JSON.Send(c.ws, msg); err != nil {
				return err
			}
		}
	}
}

func (c *conn) read(wg *sync.WaitGroup) error {
	defer func() {
		h.unregister <- c
		c.ws.Close()
		wg.Done()
	}()

	//c.ws.SetReadDeadline(time.Now().Add(pongWait))

	for {
		var id string // bar ID
		if err := websocket.Message.Receive(c.ws, &id); err != nil {
			fmt.Errorf("socket error:%v", err)
			break
		}
		if c.userID != "" {

			total := db.save(id, c.userID)
			msg := &Message{ID: id, Total: total}
			h.broadcast <- msg
		}
	}
	return nil
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

var h = hub{
	broadcast:   make(chan *Message),
	unregister:  make(chan *conn),
	register:    make(chan *conn),
	connections: make(map[*conn]bool),
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

func getUserID(c *echo.Context) string {
	if userID := c.Get("userid"); userID != nil {
		return userID.(string)
	}
	return ""
}

func authenticator() echo.HandlerFunc {
	return func(c *echo.Context) error {
		// token will either be in header or query string (e.g. sockets)
		auth := ""
		header := c.Request().Header.Get("Authorization")
		if header == "" {
			// try the query string
			auth = c.Query("jwt-token")
		} else {
			parts := strings.Split(header, "Bearer")
			if len(parts) < 2 {
				return nil
			}
			auth = strings.Trim(parts[1], " ")
		}
		if auth == "" {
			return nil
		}
		t, err := jwt.Parse(auth, func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		})
		if err != nil {
			//check if timeout etc
			log.Println("JWTERROR", err)
			return nil
		}
		if t.Valid {
			c.Set("userid", t.Claims["userid"])
		} else {
			fmt.Println("NOTVALID")
		}
		return nil
	}
}

func main() {

	// tbd: we need to be able to store the current user
	// and location in the session. The web client should
	// then "phone home" to get this info.

	e := echo.New()
	e.SetDebug(true)
	e.Use(mw.Logger())
	e.Use(mw.Recover())

	store := session.NewCookieStore([]byte(os.Getenv("SECRET_KEY")))
	e.Use(session.Sessions("nightsync", store))

	// authentication middleware
	e.Use(authenticator())

	// we want to use JWT for authentication
	// should be middleware/func for it
	twitterKey := os.Getenv("TWITTER_KEY")
	twitterSecret := os.Getenv("TWITTER_SECRET")

	goth.UseProviders(
		twitter.New(twitterKey, twitterSecret,
			"http://localhost:4000/auth/callback/?provider=twitter",
		),
	)
	gothic.Store = store

	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		Debug:            false,
	})
	e.Use(cors.Handler)

	authOptions := &yelp.AuthOptions{
		ConsumerKey:       os.Getenv("YELP_CONSUMER_KEY"),
		ConsumerSecret:    os.Getenv("YELP_CONSUMER_SECRET"),
		AccessToken:       os.Getenv("YELP_ACCESS_TOKEN"),
		AccessTokenSecret: os.Getenv("YELP_ACCESS_TOKEN_SECRET"),
	}

	e.Get("/search/", func(c *echo.Context) error {

		location := c.Query("location")
		if location == "" {
			return echo.NewHTTPError(http.StatusBadRequest)
		}

		searchOptions := yelp.SearchOptions{
			LocationOptions: &yelp.LocationOptions{
				Location: location,
			},
			GeneralOptions: &yelp.GeneralOptions{
				CategoryFilter: "bars",
			},
		}

		client := yelp.New(authOptions, nil)
		result, err := client.DoSearch(searchOptions)
		if err != nil {
			return err
		}

		bars := make([]Bar, len(result.Businesses))
		userID := getUserID(c)

		for i, biz := range result.Businesses {
			bars[i] = Bar{
				biz.ID,
				biz.ImageURL,
				biz.Name,
				biz.SnippetText,
				db.getTotal(biz.ID),
				db.isGoing(biz.ID, userID),
			}
		}
		return c.JSON(http.StatusOK, bars)
	})

	// tbd: fix the CPU usage
	e.WebSocket("/ws/", func(c *echo.Context) error {
		ws := c.Socket()
		// tbd: pass the user ID to the connection
		cn := &conn{send: make(chan *Message), ws: ws, userID: getUserID(c)}
		h.register <- cn

		var wg sync.WaitGroup
		wg.Add(2)
		go cn.write(&wg)
		go cn.read(&wg)
		wg.Wait()
		return nil
	})

	auth := e.Group("/auth/")

	auth.Get("user/", func(c *echo.Context) error {
		return c.String(http.StatusOK, getUserID(c))
	})

	// redirects to provider
	auth.Get("redirect/", func(c *echo.Context) error {
		url, err := gothic.GetAuthURL(c.Response(), c.Request())
		if err != nil {
			return err
		}
		return c.Redirect(http.StatusTemporaryRedirect, url)
	})

	// oauth provider callback
	auth.Get("callback/", func(c *echo.Context) error {

		creds, err := gothic.CompleteUserAuth(c.Response(), c.Request())
		if err != nil {
			return err
		}
		expires := time.Now().Add(time.Hour * 24)
		userID := fmt.Sprintf("%s:%s", creds.Provider, creds.UserID)

		token := jwt.New(jwt.SigningMethodRS256)
		token.Claims["userid"] = userID
		token.Claims["exp"] = expires.Unix()
		tokenStr, err := token.SignedString(signKey)
		if err != nil {
			return err
		}
		// the client can now just read the token from the query string
		url := fmt.Sprintf("http://localhost:8080?jwt-token=%s", tokenStr)
		return c.Redirect(http.StatusTemporaryRedirect, url)

	})

	// kickoff the connection hub
	go h.run()

	e.Run(":4000")

}
