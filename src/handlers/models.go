package handlers

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
