package timer

import (
	"log"
	"time"

	"golang.org/x/sys/unix"
)

// GetNanosecSinceBoot returns the nanoseconds since system boot time
func GetNanosecSinceBoot() uint64 {
	var ts unix.Timespec

	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)

	if err != nil {
		log.Println("Could not get MONOTONIC Clock time ", err)
		return 0
	}
	return uint64(ts.Nsec + ts.Sec*int64(time.Second))
}
