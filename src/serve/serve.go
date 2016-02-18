package serve

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

var db = initDB()

// grabs user ID from context
func getUserID(c *echo.Context) string {
	if userID := c.Get("userid"); userID != nil {
		return userID.(string)
	}
	return ""
}

// authentication middleware: decodes JWT token
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

// Run runs the application.
func Run(host string) {

	e := echo.New()
	e.SetDebug(true)
	e.Use(mw.Logger())
	e.Use(mw.Recover())

	e.Use(authenticator())

	h := initHub()

	twitterKey := os.Getenv("TWITTER_KEY")
	twitterSecret := os.Getenv("TWITTER_SECRET")

	goth.UseProviders(
		twitter.New(twitterKey, twitterSecret,
			"http://localhost:4000/auth/callback/?provider=twitter",
		),
	)
	gothic.Store = session.NewCookieStore([]byte(os.Getenv("SECRET_KEY")))

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
		cn := &conn{
			send: make(chan *Message),
			ws:   ws, userID: getUserID(c),
			h: h}
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
		url := fmt.Sprintf("%s?jwt-token=%s", clientURL, tokenStr)
		return c.Redirect(http.StatusTemporaryRedirect, url)

	})

	// kickoff the connection hub

	go h.run()

	e.Run(host)

}
