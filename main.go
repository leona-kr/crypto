package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const temp = ".temp"

func isError(err error) bool {
	if err != nil {
		fmt.Println(err.Error())
	}
	return (err != nil)
}

// key 16 bytes (AES-128) or 32 (AES-256)
func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}
func (x *ecbEncrypter) BlockSize() int { return x.blockSize }
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}
func (x *ecbDecrypter) BlockSize() int { return x.blockSize }
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func encrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, _ := aes.NewCipher(key)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		isError(err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		isError(err)
	}

	ciphertext := aesgcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		isError(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		isError(err)
	}

	nonceSize := aesgcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		isError(err)
	}
	return plaintext
}

func aesEncrypt(content []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		isError(err)
	}

	ecb := NewECBEncrypter(block)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	return crypted
}

func aesDecrypt(crypted []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("err is:", err)
	}

	blockMode := NewECBDecrypter(block)
	originData := make([]byte, len(crypted))
	blockMode.CryptBlocks(originData, crypted)
	originData = PKCS5UnPadding(originData)
	return originData
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func encryptFile(filename string, passphrase string) {
	file, err := os.OpenFile(
		filename,
		os.O_RDWR,
		os.FileMode(0644))
	if err != nil {
		isError(err)
	}

	newFile, err := os.Create(filename + temp)
	if err != nil {
		isError(err)
	}

	defer os.Rename(filename+temp, filename)
	defer os.Remove(filename)
	defer newFile.Close()
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		isError(err)
	}

	var data = make([]byte, fi.Size())

	_, err = file.Read(data) // 파일의 내용을 읽어서 바이트 슬라이스에 저장
	if err != nil {
		isError(err)
	}

	// crypted := encrypt(data, passphrase)
	crypted := aesEncrypt(data, passphrase)

	_, err = newFile.Write(crypted)
	if err != nil {
		isError(err)
	}
}

func decryptFile(filename string, passphrase string) {
	file, err := os.OpenFile(
		filename,
		os.O_RDWR,
		os.FileMode(0644))
	if err != nil {
		isError(err)
	}

	newFile, err := os.Create(filename + temp)
	if err != nil {
		isError(err)
	}

	defer os.Rename(filename+temp, filename)
	defer os.Remove(filename)
	defer newFile.Close()
	defer file.Close()

	data, err := ioutil.ReadFile(filename)

	// plain := decrypt(data, passphrase)
	plain := aesDecrypt(data, passphrase)
	_, err = newFile.Write(plain)
	if err != nil {
		isError(err)
	}
}

func main() {
	var mode, file string

	fmt.Println("[0]encrypt [1]decrypt | filename")
	fmt.Scanln(&mode, &file)

	if file == "" {
		fmt.Println("파일명 미입력")
		return
	}
	if mode == "0" {
		fmt.Println("encrypt start!! >>>>>>>>>>>>")
		encryptFile(file, "password")
		fmt.Println("<<<<<<<<<<<< encrypt finish!!")
	} else if mode == "1" {
		fmt.Println("decrypt start!! >>>>>>>>>>>>")
		decryptFile(file, "password")
		fmt.Println("<<<<<<<<<<<< decrypt finish!!")
	} else {
		fmt.Println("입력 번호 오류")
	}
}
