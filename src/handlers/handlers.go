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

	"goji.io"
	"goji.io/pat"
	"golang.org/x/net/context"

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

func renderJSON(w http.ResponseWriter, status int, payload interface{}) error {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(payload)
}

// grabs user ID from context
func getUserID(ctx context.Context) string {
	if userID, ok := ctx.Value(userContextKey).(string); ok {
		return userID
	}
	return ""
}

func authenticate(h goji.Handler) goji.Handler {

	return goji.HandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {

		// parse the header, fall back to "jwt-token" query parameter
		auth := ""
		header := r.Header.Get("Authorization")
		if header == "" {
			// try the query string
			auth = r.URL.Query().Get("jwt-token")
		} else {
			parts := strings.Split(header, "Bearer")
			if len(parts) > 1 {
				auth = strings.Trim(parts[1], " ")
			}
		}
		if auth == "" {
			h.ServeHTTPC(ctx, w, r)
			return
		}

		// we have a valid auth header/query parameter

		t, err := jwt.Parse(auth, func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		})

		if err != nil {
			// if a timeout throw a 401, so we can prompt re-login
			http.Error(w, "session timeout", http.StatusUnauthorized)
			return
		}
		if t.Valid {
			ctx = context.WithValue(ctx, userContextKey, t.Claims["userid"])
		}

		h.ServeHTTPC(ctx, w, r)

	})

}

func socket(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cn := &conn{
		send:   make(chan *Message),
		ws:     ws,
		userID: getUserID(ctx),
		h:      h}
	h.register <- cn

	var wg sync.WaitGroup
	wg.Add(2)
	go cn.write(&wg)
	go cn.read(&wg)
	wg.Wait()
}

func oauthCallback(w http.ResponseWriter, r *http.Request) {
	creds, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	expires := time.Now().Add(time.Hour * 24)
	userID := fmt.Sprintf("%s:%s", creds.Provider, creds.UserID)

	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims["userid"] = userID
	token.Claims["exp"] = expires.Unix()
	tokenStr, err := token.SignedString(signKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// the client can now just read the token from the query string
	url := fmt.Sprintf("%s?jwt-token=%s", clientURL, tokenStr)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func searchLocation(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	location := r.URL.Query().Get("location")
	if location == "" {
		http.Error(w, "location required", http.StatusBadRequest)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	bars := make([]Bar, len(result.Businesses))
	userID := getUserID(ctx)

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
	renderJSON(w, http.StatusOK, bars)
}

// Run runs the application.
func Run(host string) {

	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		Debug:            false,
	})

	router := goji.NewMux()

	// middlewares
	router.Use(cors.Handler)
	router.UseC(authenticate)

	router.HandleFuncC(pat.Get("/search/"), searchLocation)
	router.HandleFuncC(pat.Get("/ws/"), socket)

	auth := goji.SubMux()

	// oauth provider callback
	auth.HandleFunc(pat.Get("/callback/"), oauthCallback)

	// redirects to provider
	auth.HandleFunc(pat.Get("/redirect/"), gothic.BeginAuthHandler)

	router.HandleC(pat.New("/auth/*"), auth)

	// kickoff the connection hub

	go h.run()

	if err := http.ListenAndServe(host, router); err != nil {
		log.Fatal(err)
	}

}
