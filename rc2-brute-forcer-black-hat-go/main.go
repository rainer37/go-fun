package main

import (
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/joeljunstrom/go-luhn"
	"github.com/rainer37/go-func/rc2-brute-forcer-black-hat-go/rc2"
	log "github.com/sirupsen/logrus"
	"os"
	"regexp"
	"sync"
)

var numericPattern = regexp.MustCompile(`^\d{8}$`)

const (
	card0 = "4532651325506680"
	//cipher0   = "0986f2cc1ebdc5c2e25d04a136fa1a6b"
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
	plaintext := make([]byte, len(ciphertext)) // same len as cipher

	wg.Add(1)
	go func() {
		defer wg.Done()
		for data := range in {
			select {
			case <-done:
				return
			default:
				if data.rc2DecryptWithCondition(plaintext, ciphertext, 16, numericPattern.Match, luhn.Valid) {
					log.Infof("Card [%s] found using key [%x]", plaintext, data.key)
					close(done)
					return
				}
			}
		}
	}()
}

// iterate through decrypted ciphers to check with probe and validate functions within cipherLen
func (cd CryptoData) rc2DecryptWithCondition(dst, ciphertext []byte, cipherLen int, probe func([]byte) bool, validate func(string) bool) bool {
	size := rc2.BlockSize
	if cap(dst) < cipherLen {
		log.Fatalln("dst too small to hold decrypted plaintext")
	}

	cd.rc2Decrypt(dst, ciphertext, 0)
	if !probe(dst[:size]) {
		return false
	}
	for offset := size; offset < cipherLen; offset += size {
		cd.rc2Decrypt(dst, ciphertext, offset)
		if !probe(dst[offset:offset+size]) || !validate(string(dst)) {
			return false
		}
	}
	return true
}

func (cd CryptoData) rc2Decrypt(dst, ciphertext []byte, offset int) {
	cd.block.Decrypt(dst[offset:], ciphertext[offset:])
}

func (cd CryptoData) rc2EncryptOneBlock(ciphertext, src []byte, offset int) {
	cd.block.Encrypt(ciphertext[offset:], src[offset:])
}

func (cd CryptoData) rc2Encrypt(ciphertext []byte, src []byte) {
	if cap(ciphertext) < len(src) {
		panic("dst is too small")
	}
	if len(src)%rc2.BlockSize != 0 {
		panic("TODO needs to add padding")
	}

	for offset := 0; offset < len(src); offset += rc2.BlockSize {
		cd.rc2EncryptOneBlock(ciphertext, src, offset)
	}
}

func encryptWithRC2(plain string, rc2key uint64) string {
	key := keyCut5Bytes(rc2key)
	block, err := rc2.New(key[:], Rc2KeyLen)
	if err != nil {
		log.Fatalln(err)
	}
	cd := CryptoData{block, key[:]}

	ciph := make([]byte, 16)
	cd.rc2Encrypt(ciph, []byte(plain))

	return fmt.Sprintf("%x", ciph)
}

func main() {
	ciphertext, err := hex.DecodeString(encryptWithRC2(card0, 988158147510))
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
	// generate(988158147510, 988158147510, work, done, &prodWg) // [e612d0bbb6]

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
	os.Exit(1)
}
