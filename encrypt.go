package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var (
	path = flag.String("path", "", "path to file to encrypt or decrypt")
	key  = flag.String("key", "", "key to use")
	enc  = flag.Bool("enc", false, "encrpytion operation")
	dec  = flag.Bool("dec", false, "decryption operation")
	out  = flag.String("out", "", "output path")
)

func main() {
	flag.Parse()

	if *path == "" || *key == "" {
		log.Fatal("path or key flag is empty or not present")
	}

	file, err := ioutil.ReadFile(*path)
	if err != nil {
		log.Fatalf("can't open file: %v", err)
	}

	keyHash, err := createHash([]byte(*key))
	if err != nil {
		log.Fatalf("can't create key hash: %v", err)
	}

	if *enc {
		if *out == "" {
			*out = *path + ".crypt"
		}
		if err = doOp(file, keyHash, *out, encrypt); err != nil {
			log.Fatalf("can't encrypt file: %v", err)
		}
	} else if *dec {
		if *out == "" {
			*out = *path + ".crypt"
		}

		outPath := (*path)[:len(*path)-6] //remove .crypt
		if err = doOp(file, keyHash, outPath, decrypt); err != nil {
			log.Fatalf("can't decrypt file: %v", err)
		}
	} else {
		log.Fatalf("no operation specified")
	}
}

func doOp(data, key []byte, outPath string, fn func([]byte, []byte) ([]byte, error)) error {
	ciphered, err := fn(data, key)
	if err != nil {
		return err
	}

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}

	if _, err = out.Write(ciphered); err != nil {
		return err
	}

	return nil
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	gcm, err := getGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	gcm, err := getGCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciph := data[:nonceSize], data[nonceSize:]

	return gcm.Open(nil, nonce, ciph, nil)
}

func createHash(key []byte) ([]byte, error) {
	hs := md5.New()
	if _, err := hs.Write(key); err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(hs.Sum(nil))), nil
}

func getGCM(key []byte) (cipher.AEAD, error) {
	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("can't create aes cipher: " + err.Error())
	}

	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		return nil, errors.New("can't create gcm: " + err.Error())
	}
	return gcm, nil
}
