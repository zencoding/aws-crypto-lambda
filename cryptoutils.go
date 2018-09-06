package main

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/GoKillers/libsodium-go/cryptogenerichash"

	"github.com/GoKillers/libsodium-go/cryptosign"
)

//Sign a String using SecretKey
func SignSimple(plainText string, secretKey string) (signString string, hashString string, errorValue error) {

	sk64Decoded, _ := b64.StdEncoding.DecodeString(secretKey)

	hashString, hashBytes := HashSimple(plainText)
	signBytes, _ := cryptosign.CryptoSignDetached(hashBytes, sk64Decoded)
	signString = b64.StdEncoding.EncodeToString([]byte(signBytes))

	return signString, hashString, nil
}

func VerifySignSimple(signText string, messageText string, hashInText string, publicKey string) (signVerified int, errorValue error) {
	//Hash the message

	sign64Decoded, _ := b64.StdEncoding.DecodeString(signText)
	public64Decoded, _ := b64.StdEncoding.DecodeString(publicKey)
	hashString, hashBytes := HashSimple(messageText)
	if hashString != hashInText {
		fmt.Println("Hash Check Failed")
		return -1, errors.New("Hash Check Failed")
	}

	return cryptosign.CryptoSignVerifyDetached(sign64Decoded, hashBytes, public64Decoded), nil

}

//Hash a Message and return Hash String
func HashSimple(message string) (hashString string, hashBytes []byte) {
	//Pass Byte array to hash
	m := make([]byte, len(message))
	copy(m, message)

	k := make([]byte, generichash.CryptoGenericHashKeyBytes())
	hashBytes, _ = generichash.CryptoGenericHash(generichash.CryptoGenericHashBytes(), m, k)
	hashString = b64.StdEncoding.EncodeToString(hashBytes)
	return hashString, hashBytes
}

//Hash a Message and return Hash String
func HashFileSimple(inputFilePath string) (hashString string, hashBytes []byte, errorValue error) {
	file, err := os.Open(inputFilePath)
	if err != nil {
		fmt.Println(err)
		return "", nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println(err)
		return "", nil, err
	}
	fileSize := fileInfo.Size()
	buffer := make([]byte, fileSize)

	bytesread, err := file.Read(buffer)
	if err != nil {
		fmt.Println(err)
		return "", nil, err
	}
	fmt.Println("Bytes read: ", bytesread)
	k := make([]byte, generichash.CryptoGenericHashKeyBytes())
	hashBytes, _ = generichash.CryptoGenericHash(generichash.CryptoGenericHashBytes(), buffer, k)
	hashString = b64.StdEncoding.EncodeToString(hashBytes)
	return hashString, hashBytes, nil
}

func SignFileSimple(inputFilePath string, secretKey string) (signString string, hashString string, errorValue error) {

	sk64Decoded, _ := b64.StdEncoding.DecodeString(secretKey)
	hashString, hashBytes, _ := HashFileSimple(inputFilePath)

	signBytes, _ := cryptosign.CryptoSignDetached(hashBytes, sk64Decoded)
	signString = b64.StdEncoding.EncodeToString([]byte(signBytes))

	return signString, hashString, nil
}

func VerifyFileSimple(signText string, inputFilePath string, hashInText string, publicKey string) (signVerified int, errorValue error) {
	//Hash the message

	sign64Decoded, _ := b64.StdEncoding.DecodeString(signText)
	public64Decoded, _ := b64.StdEncoding.DecodeString(publicKey)
	hashString, hashBytes, _ := HashFileSimple(inputFilePath)

	if hashString != hashInText {
		fmt.Println("Hash Check Failed")
		return -1, nil
	}

	return cryptosign.CryptoSignVerifyDetached(sign64Decoded, hashBytes, public64Decoded), nil

}
