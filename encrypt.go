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
	"log"
	"os"
	"strings"
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

	fileBytes, outFile := getBytesAndOut(path, out, enc)

	keyHash, err := createHash([]byte(*key))
	if err != nil {
		log.Fatalf("can't create key hash: %v", err)
	}

	if *enc {
		if err = doOp(fileBytes, keyHash, outFile, encrypt); err != nil {
			log.Fatalf("can't encrypt file: %v", err)
		}
	} else if *dec {
		if err = doOp(fileBytes, keyHash, outFile, decrypt); err != nil {
			log.Fatalf("can't decrypt file: %v", err)
		}
	} else {
		log.Fatalf("no operation specified")
	}
}

// doOp performs perfoms an fn which should be either encrypt or decrypt
// on data and key
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

// encrypt encrypts data using key
func encrypt(data []byte, key []byte) ([]byte, error) {
	gcm, err := getGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decrypt decrypts data using key
func decrypt(data []byte, key []byte) ([]byte, error) {
	gcm, err := getGCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciph := data[:nonceSize], data[nonceSize:]

	return gcm.Open(nil, nonce, ciph, nil)
}

// createHash returns a hashed form of key
func createHash(key []byte) ([]byte, error) {
	hs := md5.New()
	if _, err := hs.Write(key); err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(hs.Sum(nil))), nil
}

// getGCM returns a GCM that will be used in
// decryption or encryption
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

// getBytesAndOut returns the file bytes of path,
// and determines the output path to use
// isEnc tells whether it's encryption/decryption
// to be performed.
func getBytesAndOut(path *string, outPath *string, isEnc *bool) ([]byte, string) {
	file, err := os.Open(*path)
	if err != nil {
		log.Fatalf("can't open file: %v", err)
	}

	// read file stats
	info, err := file.Stat()
	if err != nil {
		log.Fatalf("can't read file stats: %v", err)
	}

	// use info.Size to determine file size to avoid reallocations
	fileBytes := make([]byte, info.Size())
	_, err = io.ReadFull(file, fileBytes)

	const crypt = ".crypt"
	if *isEnc {
		if *outPath == "" {
			*outPath = *path + crypt
		} else {
			*outPath = *outPath + info.Name() + crypt
		}
	} else {
		if *outPath == "" {
			*outPath = strings.TrimSuffix(*path, crypt)
		} else {
			*outPath = *outPath + strings.TrimSuffix(info.Name(), crypt)
		}
	}
	return fileBytes, *outPath
}
