package main

import (
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"github.com/joeljunstrom/go-luhn"
	"github.com/rainer37/go-func/rc2-brute-forcer-black-hat-go/rc2"
	log "github.com/sirupsen/logrus"
	"regexp"
	"sync"
)

var numericPattern = regexp.MustCompile(`^\d{8}$`)

const (
	cipher0   = "0986f2cc1ebdc5c2e25d04a136fa1a6b"
	Rc2KeyLen = 40
	numProd   = 75
	numCons   = 30
)

type CryptoData struct {
	block cipher.Block
	key   []byte
}

func keyCut5Bytes(keyNum uint64) [5]byte {
	sl := make([]byte, 8)
	binary.BigEndian.PutUint64(sl, keyNum)
	var key [5]byte
	copy(key[:], sl[3:8])
	return key
}

func generate(start, end uint64, out chan<- *CryptoData, done <-chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := start; i <= end; i++ {
			select {
			case <-done:
				return
			default:
				key := keyCut5Bytes(i)
				block, err := rc2.New(key[:], Rc2KeyLen)
				if err != nil {
					log.Fatalln(err)
				}
				data := &CryptoData{block, key[:]}
				out <- data
			}
		}
	}()
	return
}

func decrypt(ciphertext []byte, in <-chan *CryptoData, done chan struct{}, wg *sync.WaitGroup) {
	size := rc2.BlockSize
	plaintext := make([]byte, len(ciphertext)) // same len as cipher

	wg.Add(1)
	go func() {
		defer wg.Done()
		for data := range in {
			select {
			case <-done:
				return
			default:
				data.block.Decrypt(plaintext[:size], ciphertext[:size])
				if numericPattern.Match(plaintext[:size]) {
					data.block.Decrypt(plaintext[size:], ciphertext[size:])
					if luhn.Valid(string(plaintext)) && numericPattern.Match(plaintext[size:]) {
						log.Infof("Card [%s] found using key [%x]", plaintext, data.key)
						close(done)
						return
					}
				}
			}
		}
	}()
}

func main() {
	ciphertext, err := hex.DecodeString(cipher0)
	if err != nil {
		log.Fatal(err)
	}

	var prodWg, consWg sync.WaitGroup
	var min, max, prods = uint64(0x0000000000), uint64(0xFFFFFFFFFF), uint64(numProd)
	step := (max - min) / prods

	done := make(chan struct{})
	work := make(chan *CryptoData, 100)

	if step*prods < max {
		step += prods
	}

	var start, end = min, min + step
	log.Info("starting producers...")
	for i := uint64(0); i < prods; i++ {
		if end > max {
			end = max
		}
		generate(start, end, work, done, &prodWg)
		end += step
		start += step
	}
	generate(988158147510, 988158147510, work, done, &prodWg) // [e612d0bbb6]

	log.Info("Producers ready!")
	log.Info("starting consumers...")
	for i := 0; i < numCons; i++ {
		decrypt(ciphertext, work, done, &consWg)
	}

	log.Info("Consumers ready!")
	prodWg.Wait()
	close(work)
	consWg.Wait()
	log.Info("Brute-force complete")
}
