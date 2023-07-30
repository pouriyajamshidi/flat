package flowtable

import (
	"log"
	"sync"
	"time"

	"github.com/pouriyajamshidi/flat/internal/timer"
)

type FlowTable struct {
	Ticker *time.Ticker
	sync.Map
}

// NewFlowTable Constructs a new FlowTable
func NewFlowTable() *FlowTable {
	return &FlowTable{Ticker: time.NewTicker(time.Second * 10)}
}

// add adds packet hash and its timestamp to the FlowTable
func (table *FlowTable) Insert(hash, timestamp uint64) {
	table.Store(hash, timestamp)
}

// load loads packet hash and its timestamp from the FlowTable
func (table *FlowTable) Get(hash uint64) (uint64, bool) {
	value, ok := table.Load(hash)

	if !ok {
		return 0, ok
	}
	return value.(uint64), true
}

// delete deletes packet hash and its timestamp from the FlowTable
func (table *FlowTable) Remove(hash uint64) {
	_, found := table.Load(hash)

	if found {
		// log.Printf("Removing hash %v from flow table", hash)
		table.Delete(hash)
	} else {
		log.Printf("hash %v is not in flow table", hash)
	}
}

// Prune clears the stale entries (older than 10 seconds) from the FlowTable
func (table *FlowTable) Prune() {
	now := timer.GetNanosecSinceBoot()

	table.Range(func(hash, timestamp interface{}) bool {
		if (now-timestamp.(uint64))/1000000 > 10000 {
			log.Printf("Pruning stale entry from flow table: %v", hash)

			table.Delete(hash)

			return true
		}
		return false
	})
}
