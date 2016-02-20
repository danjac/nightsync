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

	"github.com/justinas/alice"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitter"
)

var (
	verifyKey   *rsa.PublicKey
	signKey     *rsa.PrivateKey
	authOptions *yelp.AuthOptions
)

var (
	db = initDB()
	h  = initHub()
)

const (
	privKeyPath    = "keys/app.rsa"     // openssl genrsa -out app.rsa keysize
	pubKeyPath     = "keys/app.rsa.pub" // openssl rsa -in app.rsa -pubout > app.rsa.pub
	clientURL      = "http://localhost:8080"
	userContextKey = "userid"
)

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

	authOptions = &yelp.AuthOptions{
		ConsumerKey:       os.Getenv("YELP_CONSUMER_KEY"),
		ConsumerSecret:    os.Getenv("YELP_CONSUMER_SECRET"),
		AccessToken:       os.Getenv("YELP_ACCESS_TOKEN"),
		AccessTokenSecret: os.Getenv("YELP_ACCESS_TOKEN_SECRET"),
	}

	twitterKey := os.Getenv("TWITTER_KEY")
	twitterSecret := os.Getenv("TWITTER_SECRET")

	goth.UseProviders(
		twitter.New(twitterKey, twitterSecret,
			"http://localhost:4000/auth/callback/?provider=twitter",
		),
	)

	gothic.Store = sessions.NewCookieStore([]byte(os.Getenv("SECRET_KEY")))
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type httpError struct {
	status int
}

func (e httpError) Error() string {
	return http.StatusText(e.status)
}

func newHTTPError(status int) error {
	return httpError{status}
}

func renderJSON(w http.ResponseWriter, status int, payload interface{}) error {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(payload)
}

func handleError(w http.ResponseWriter, err error) {
	if httpError, ok := err.(httpError); ok {
		http.Error(w, httpError.Error(), httpError.status)
		return
	}
	// maybe catch other errors such as "no rows found"
	log.Println(err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// grabs user ID from context
func getUserID(r *http.Request) string {
	if userID := context.Get(r, userContextKey); userID != nil {
		return userID.(string)
	}
	return ""
}

func authenticate(w http.ResponseWriter, r *http.Request) error {
	auth := ""
	header := r.Header.Get("Authorization")
	if header == "" {
		// try the query string
		auth = r.URL.Query().Get("jwt-token")
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
		// if a timeout throw a 401, so we can prompt re-login
		return newHTTPError(http.StatusUnauthorized)
	}
	if t.Valid {
		context.Set(r, userContextKey, t.Claims["userid"])
	} else {
		fmt.Println("NOTVALID")
	}
	return nil
}

type handlerFunc func(http.ResponseWriter, *http.Request) error

type handler struct {
	H handlerFunc
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := authenticate(w, r); err != nil {
		handleError(w, err)
		return
	}
	if err := h.H(w, r); err != nil {
		handleError(w, err)
	}
}

func newHandler(h handlerFunc) http.Handler {
	return handler{h}
}

func socket(w http.ResponseWriter, r *http.Request) error {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
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
	return nil

}

func authCallback(w http.ResponseWriter, r *http.Request) error {
	creds, err := gothic.CompleteUserAuth(w, r)
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
	url := fmt.Sprintf("%s?jwt-token=%s", clientURL, tokenStr)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	return nil
}

func searchLocation(w http.ResponseWriter, r *http.Request) error {
	location := r.URL.Query().Get("location")
	if location == "" {
		return newHTTPError(http.StatusBadRequest)
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
	return renderJSON(w, http.StatusOK, bars)
}

// Run runs the application.
func Run(host string) {

	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		Debug:            false,
	})

	router := mux.NewRouter()

	router.Handle("/search/", newHandler(searchLocation)).Methods("GET")
	router.Handle("/ws/", newHandler(socket)).Methods("GET")

	auth := router.PathPrefix("/auth").Subrouter()

	// oauth provider callback
	auth.Handle("/callback/", newHandler(authCallback))

	// redirects to provider
	auth.HandleFunc("/redirect/", gothic.BeginAuthHandler)

	// kickoff the connection hub

	go h.run()

	chain := alice.New(cors.Handler).Then(router)

	if err := http.ListenAndServe(host, chain); err != nil {
		log.Fatal(err)
	}

}
