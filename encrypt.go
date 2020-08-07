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
	// call fn on data & key and get the encrypted data
	ciphered, err := fn(data, key)
	if err != nil {
		return err
	}

	// create the output file
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}

	// write the encrypted data out
	if _, err = out.Write(ciphered); err != nil {
		return err
	}

	return nil
}

// encrypt encrypts data using key
func encrypt(data []byte, key []byte) ([]byte, error) {
	// get a gcm using key
	gcm, err := getGCM(key)
	if err != nil {
		return nil, err
	}

	// get the Nonce Size and make a []byte with that length
	nonce := make([]byte, gcm.NonceSize())

	// read random data into nonce, this ensures stronger encryption
	io.ReadFull(rand.Reader, nonce)

	// return the encrypted data using nonce as the dst,
	// so the encrypted data will be added to nonce and
	// stored with it
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decrypt decrypts data using key
func decrypt(data []byte, key []byte) ([]byte, error) {
	// get a gcm using key
	gcm, err := getGCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize() //get the Nonce Size
	// use nonceSize to seperate the nonce from the actual
	// encrypted data
	nonce, ciph := data[:nonceSize], data[nonceSize:]

	// decrypt ciph
	return gcm.Open(nil, nonce, ciph, nil)
}

// createHash returns a hashed form of key
func createHash(key []byte) ([]byte, error) {
	hs := md5.New() // get new md5 hash
	// write key to the hash
	if _, err := hs.Write(key); err != nil {
		return nil, err
	}
	// encode the hash bytes to string, convert that to a []byte
	// and then return
	return []byte(hex.EncodeToString(hs.Sum(nil))), nil
}

// getGCM returns a GCM that will be used in
// decryption or encryption
func getGCM(key []byte) (cipher.AEAD, error) {
	ciph, err := aes.NewCipher(key) //get a new aes cipher with key
	if err != nil {
		return nil, errors.New("can't create aes cipher: " + err.Error())
	}

	// get a new GCM using ciph
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
	if *isEnc { // if encrpytion is occuring, append crypt to *outPath
		// if *outPath is empty use *path
		if *outPath == "" {
			*outPath = *path + crypt
		} else {
			// else use the file name and append crypt to it
			*outPath = *outPath + info.Name() + crypt
		}
	} else { // decryption is occurring, remove crypt from the filename
		if *outPath == "" {
			// // if *outPath is empty use *path
			*outPath = strings.TrimSuffix(*path, crypt)
		} else {
			// else remove crypt from filename and append to *outPath
			*outPath = *outPath + strings.TrimSuffix(info.Name(), crypt)
		}
	}
	return fileBytes, *outPath
}
