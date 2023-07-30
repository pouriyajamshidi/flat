package timer

// #cgo CFLAGS: -g -Wall
/*
#include <time.h>

static unsigned long long get_nsecs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"

func GetNanosecSinceBoot() uint64 {
	return uint64(C.get_nsecs())
}
