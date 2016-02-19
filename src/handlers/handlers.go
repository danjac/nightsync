package handlers

import (
	"crypto/rsa"
	"encoding/json"
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

	"github.com/codegangsta/negroni"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitter"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

const (
	privKeyPath = "keys/app.rsa"     // openssl genrsa -out app.rsa keysize
	pubKeyPath  = "keys/app.rsa.pub" // openssl rsa -in app.rsa -pubout > app.rsa.pub
)

const clientURL = "http://localhost:8080"

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

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

func handleServerError(w http.ResponseWriter, err error) {
	log.Println(err)
	http.Error(w, "Sorry, an error has occurred", http.StatusInternalServerError)
}

var (
	db = initDB()
	h  = initHub()
)

// grabs user ID from context
func getUserID(r *http.Request) string {
	if userID := context.Get(r, "userid"); userID != nil {
		return userID.(string)
	}
	return ""
}

// authentication middleware: decodes JWT token
func authenticator(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// token will either be in header or query string (e.g. sockets)
	auth := ""
	header := r.Header.Get("Authorization")
	if header == "" {
		// try the query string
		auth = r.URL.Query().Get("jwt-token")
	} else {
		parts := strings.Split(header, "Bearer")
		if len(parts) < 2 {
			next(w, r)
			return
		}
		auth = strings.Trim(parts[1], " ")
	}
	if auth == "" {
		next(w, r)
		return
	}
	t, err := jwt.Parse(auth, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		//check if timeout etc
		log.Println("JWTERROR", err)
		next(w, r)
		return
	}
	if t.Valid {
		context.Set(r, "userid", t.Claims["userid"])
	} else {
		fmt.Println("NOTVALID")
	}
	next(w, r)
}

// Run runs the application.
func Run(host string) {

	twitterKey := os.Getenv("TWITTER_KEY")
	twitterSecret := os.Getenv("TWITTER_SECRET")

	goth.UseProviders(
		twitter.New(twitterKey, twitterSecret,
			"http://localhost:4000/auth/callback/?provider=twitter",
		),
	)
	gothic.Store = sessions.NewCookieStore([]byte(os.Getenv("SECRET_KEY")))

	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		Debug:            false,
	})

	authOptions := &yelp.AuthOptions{
		ConsumerKey:       os.Getenv("YELP_CONSUMER_KEY"),
		ConsumerSecret:    os.Getenv("YELP_CONSUMER_SECRET"),
		AccessToken:       os.Getenv("YELP_ACCESS_TOKEN"),
		AccessTokenSecret: os.Getenv("YELP_ACCESS_TOKEN_SECRET"),
	}

	router := mux.NewRouter()

	router.HandleFunc("/search/", func(w http.ResponseWriter, r *http.Request) {

		location := r.URL.Query().Get("location")
		if location == "" {
			http.Error(w, "Location required", http.StatusBadRequest)
			return
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
			handleServerError(w, err)
			return
		}

		bars := make([]Bar, len(result.Businesses))
		userID := getUserID(r)

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
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(bars); err != nil {
			handleServerError(w, err)
		}
	})

	router.HandleFunc("/ws/", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			handleServerError(w, err)
			return
		}
		cn := &conn{
			send:   make(chan *Message),
			ws:     ws,
			userID: getUserID(r),
			h:      h}
		h.register <- cn

		var wg sync.WaitGroup
		wg.Add(2)
		go cn.write(&wg)
		go cn.read(&wg)
		wg.Wait()
	})

	auth := router.PathPrefix("/auth").Subrouter()

	// redirects to provider
	auth.HandleFunc("/redirect/", gothic.BeginAuthHandler)

	// oauth provider callback
	auth.HandleFunc("/callback/", func(w http.ResponseWriter, r *http.Request) {

		creds, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			handleServerError(w, err)
			return
		}
		expires := time.Now().Add(time.Hour * 24)
		userID := fmt.Sprintf("%s:%s", creds.Provider, creds.UserID)

		token := jwt.New(jwt.SigningMethodRS256)
		token.Claims["userid"] = userID
		token.Claims["exp"] = expires.Unix()
		tokenStr, err := token.SignedString(signKey)
		if err != nil {
			handleServerError(w, err)
			return
		}
		// the client can now just read the token from the query string
		url := fmt.Sprintf("%s?jwt-token=%s", clientURL, tokenStr)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	// kickoff the connection hub

	go h.run()

	n := negroni.Classic()
	n.Use(cors)
	n.Use(negroni.HandlerFunc(authenticator))
	n.UseHandler(router)
	n.Run(host)

}
