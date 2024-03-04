/**
a program to hopefully help vet Raven

Micah Sherr <msherr@cs.georgetown.edu>

*/

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"time"
)

// Wrapper for debug level logging using the RACE Logging API call
func logDebug(msg ...interface{}) {
	log.Println("[raven-debug]", fmt.Sprint(msg...), "")
}

// Wrapper for info level logging using the RACE Logging API call
func logInfo(msg ...interface{}) {
	log.Println("[raven-info]", fmt.Sprint(msg...), "")
}

// Wrapper for warn level logging using the RACE Logging API call
func logWarning(msg ...interface{}) {
	log.Println("[raven-info]", fmt.Sprint(msg...), "")
}

// Wrapper for error level logging using the RACE Logging API call
func logError(msg ...interface{}) {
	log.Fatalln("[raven-error]", fmt.Sprint(msg...), "")
}

/**
defines a bunch of routines for quasi-thoroughly testing and vetting Raven
*/
func test_main() {

	const keyfile string = "raven-keyfile.json"

	// parse some command-line options
	sendFlag := flag.Bool("send", false, "send message")
	dummyFlag := flag.Bool("dummy", false, "send dummy message")
	receiveFlag := flag.Bool("receive", false, "receive message")
	messageFlag := flag.String("message", "this is a test message", "message to send")
	bigFlag := flag.Bool("big", false, "send a really big (~3MiB) message")
	targetEmailAddress := flag.String("check", "race-server-00001@racemail-raven.test", "target email address")
	sendTime := flag.Int("sendtime", 45, "time to send messages")
	makeKeysFlag := flag.Bool("makekeys", false, "make GPG keys")
	loadKeysFlag := flag.Bool("loadkeys", false, "load GPG keys")

	flag.Parse()
	message := []byte(*messageFlag)

	if *bigFlag {
		// generate a super big message
		const big = 3 * 1024 * 1024
		message = make([]byte, big)
		n, err := rand.Read(message)
		if err != nil {
			log.Fatalf("cannot produce random number: %v\n", err)
		}
		if n != big {
			log.Fatalf("cannot produce a big (%d) random number\n", big)
		}
		*sendTime = 60
	}

	if *makeKeysFlag {
		makeKeyRing(keyfile, 300)
	}
	if *loadKeysFlag {
		keyring := loadKeyRing("raven-keyfile.json")
		fmt.Println(keyring)
	}

	if *sendFlag {
		account, err := newAccount("localhost", 587, 993, "race-client-00001@racemail-raven.test", "pass1234", keyfile)
		if err != nil {
			log.Panicln("new account: ", err)
			return
		}
		account.insecure_tls = true

		recvrs := [1]string{"race-server-00001@racemail-raven.test"}

		for it := 0; it < 3; it++ {
			id, err := account.enqueue(recvrs[:], message)
			if err != nil {
				log.Panicln("enqueue failed:", err)
			} else {
				log.Println("enqueued!  uuid=", id)
			}

			for i := 0; i < *sendTime; i++ {
				log.Printf("send iteration %v\n", i)
				err = account.send()
				if err != nil {
					log.Fatalln("send failed: ", err)
				}
				time.Sleep(time.Millisecond * 100)
			}
		}
	}

	if *dummyFlag {
		account, err := newAccount("localhost", 587, 993, *targetEmailAddress, "pass1234", keyfile)
		if err != nil {
			log.Fatalf("new account: %v", err)
			return
		}
		account.insecure_tls = true
		for i := 0; i < *sendTime; i++ {
			log.Printf("send iteration %v\n", i)
			err = account.send()
			if err != nil {
				log.Fatalln("send failed: ", err)
			} else {
				log.Println("looks like we sent a message!")
			}
			time.Sleep(time.Second * 1)
		}
	}

	if *receiveFlag {
		// let's log in again, but this time as the server
		account, err := newAccount("localhost", 587, 993, *targetEmailAddress, "pass1234", keyfile)
		if err != nil {
			log.Fatal("log in error", err)
			return
		}
		account.insecure_tls = true

		for {
			log.Println("about to call receive!")
			msgs, err := account.rcv()
			if err != nil {
				log.Fatalln("account.recv() returned error: ", err)
			}
			for n, msg := range msgs {
				hash := sha256.Sum256(msg)
				if len(msg) <= 64 {
					log.Printf("message %d (hash %v): '%s'\n", n, hex.EncodeToString(hash[:]), msg)
				} else {
					log.Printf("message %d (hash %v), len=%d'\n", n, hex.EncodeToString(hash[:]), len(msg))
				}
			}
			log.Printf("sleeping 200 milliseconds before continuing")
			time.Sleep(time.Millisecond * 200)
		}

	}
}

func main() {
	test_main()
}
