package l2cryptor

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"sync"
)

func decrypt(cipher []byte, key RSAKey) []byte {
	// decrypted message is a `cipher` ^ `key`.D mod `key`.N()
	log.Println("N is:", key.N())
	fmt.Println(key.D())
	return new(big.Int).Exp(new(big.Int).
		SetBytes(cipher), key.D(), key.N()).Bytes()
}

func decryptSequence(cipher []byte, key RSAKey) ([]byte, error) {
	buf := bytes.NewBuffer(cipher)
	outMap := &sync.Map{}
	tailSize := len(cipher) % blockSize

	var n int
	var wg sync.WaitGroup
	for buf.Len() > tailSize { // break for if whole blocks if out
		fmt.Println("Started")
		wg.Add(1)
		go func(cipher []byte, n int) {
			defer wg.Done()
			dec := decrypt(cipher, key)
			if len(dec) < 1 {
				return
			}
			sz := int(dec[0]) // get length of meaningful data in the decrypted block
			if int(sz) > len(dec)-1 {
				return
			}
			p := dec[len(dec)-sz:] // p is a payload data in the decrypted block
			outMap.Store(n, p)
		}(buf.Next(blockSize), n)
		n++
	}

	wg.Wait()

	// assembly decrypted data into ordered sequence
	out := &bytes.Buffer{}
	for i := 0; i < n; i++ {
		message, ok := outMap.Load(i)
		if !ok {
			return nil, errDetectDecryptedBlock(i)
		}
		_, err := out.Write(message.([]byte))
		if err != nil {
			return nil, err
		}
	}

	return out.Bytes(), nil
}
