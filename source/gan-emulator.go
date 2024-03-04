//
//	Golang implementation of Raven
//
//	Eliana Troper and Micah Sherr

package main

import (
	"crypto/rand"
	"log"
	"math"
	"math/big"
	"time"
)

const min_slot_size int64 = 1000
const max_slot_size int64 = 250000
const min_seconds_from_now float64 = 0
const max_seconds_from_now float64 = 5

/*
returns a float between [0,1)
*/
func genRandomFloat() (f float64) {
	// taken from https://stackoverflow.com/questions/68728890/golang-how-to-generate-random-float-using-only-crypto-rand
	a, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		log.Fatalln(err)
	}
again:
	f = float64(a.Int64()) / (1 << 63)
	if f == 1 {
		goto again // resample; this branch is taken O(never)
	}
	return
}

func SlotGenerator(c chan slot) {
	interval := big.NewInt(max_slot_size - min_slot_size)
	slot := new(slot)
	for {
		slotSize, err := rand.Int(rand.Reader, interval)
		if err != nil {
			panic(err)
		}
		size := slotSize.Int64() + min_slot_size
		slot.size = int(size)

		f := genRandomFloat()
		delay := (f * (max_seconds_from_now - min_seconds_from_now)) + min_seconds_from_now
		slot.time = time.Now().Add(time.Second * time.Duration(delay))

		slot.rcvr_ct = 0 // TODO: not sure what this is for

		c <- *slot
	}
}
