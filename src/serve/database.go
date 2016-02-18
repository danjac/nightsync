package serve

import (
	"sync"
)

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
