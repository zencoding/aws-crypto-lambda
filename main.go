package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// Request for Lambda, this is a interface{} since the Request payload can be different based on operation
type Request map[string]interface{}

//Response for Lambda
type Response struct {
	Message string `json:"message"`
	OK      bool   `json:"ok"`
}

//SignResponse type to represent response for Signing Operation
type SignResponse struct {
	SignText string
	HashText string
}

//VerifySignResposne type to represent response for verification
type VerifySignResposne struct {
	VerifiedStatus bool
}

//Handler function to be invoked by AWS Lambda
func Handler(request Request) (Response, error) {
	operation := request["operation"]
	fmt.Println("Operation requested is ", operation)
	response := Response{Message: "", OK: false}

	switch operation {
	case "SignSimple":
		messageText := request["value"].(map[string]interface{})["messagetext"].(string)
		secretKey := request["value"].(map[string]interface{})["secretkey"].(string)
		signString, hashString, _ := SignSimple(messageText, secretKey)
		signResponse := SignResponse{signString, hashString}
		signSimpleJSON, marshalErr := json.Marshal(signResponse)
		if marshalErr != nil {
			fmt.Println("error in SignSimple Marshal:", marshalErr)
			return response, errors.New("Marshall of request failed")
		}
		response = Response{Message: string(signSimpleJSON[:]), OK: true}
	case "VerifySignSimple":

		signVerified, _ := VerifySignSimple(request["value"].(map[string]interface{})["signtext"].(string),
			request["value"].(map[string]interface{})["messagetext"].(string), request["value"].(map[string]interface{})["hashtext"].(string),
			request["value"].(map[string]interface{})["publickey"].(string))
		verifyResponse := VerifySignResposne{(signVerified == 0)}
		verifySimpleJSON, marshalErr := json.Marshal(verifyResponse)
		if marshalErr != nil {
			fmt.Println("error in VerifySignSimple Marshal:", marshalErr)
			return response, errors.New("Marshall of request failed")
		}
		response = Response{Message: string(verifySimpleJSON), OK: true}

	case "SignFileSimple":

		fileName := strings.Replace(request["value"].(map[string]interface{})["s3item"].(string), "/", "_", -1)
		file, fileOpenErr := os.Create(fileName)
		if fileOpenErr != nil {
			fmt.Println("error in Open File for S3:", fileOpenErr)
			return response, errors.New("error in Open File for S3")
		}

		defer file.Close()
		sess, _ := session.NewSession(&aws.Config{
			Region: aws.String("us-east-1")},
		)

		downloader := s3manager.NewDownloader(sess)

		numBytes, fileDownloadErr := downloader.Download(file,
			&s3.GetObjectInput{
				Bucket: aws.String(request["value"].(map[string]interface{})["s3bucket"].(string)),
				Key:    aws.String(request["value"].(map[string]interface{})["s3item"].(string)),
			})
		if fileDownloadErr != nil || numBytes == 0 {
			fmt.Println("error in Downloading File from S3:", fileDownloadErr)
			return response, errors.New("error in Downloading File from S3")
		}

		signString, hashString, _ := SignFileSimple(fileName, request["value"].(map[string]interface{})["secretkey"].(string))
		signResponse := SignResponse{signString, hashString}
		signSimpleJSON, marshalErr := json.Marshal(signResponse)
		if marshalErr != nil {
			fmt.Println("error in signFileSimpleRequest Marshal:", marshalErr)
			return response, errors.New("Marshall of request failed")
		}

		response = Response{Message: string(signSimpleJSON[:]), OK: true}
	case "VerifyFileSimple":

		fileName := strings.Replace(request["value"].(map[string]interface{})["s3item"].(string), "/", "_", -1)
		file, fileOpenErr := os.Create(fileName)
		if fileOpenErr != nil {
			fmt.Println("error in Open File for S3 in verifyFileSimpleRequest:", fileOpenErr)
			return response, errors.New("error in Open File for S3")
		}

		defer file.Close()
		sess, _ := session.NewSession(&aws.Config{
			Region: aws.String("us-east-1")},
		)

		downloader := s3manager.NewDownloader(sess)

		numBytes, fileDownloadErr := downloader.Download(file,
			&s3.GetObjectInput{
				Bucket: aws.String(request["value"].(map[string]interface{})["s3bucket"].(string)),
				Key:    aws.String(request["value"].(map[string]interface{})["s3item"].(string)),
			})
		if fileDownloadErr != nil || numBytes == 0 {
			fmt.Println("error in Downloading File from S3:", fileDownloadErr)
			return response, errors.New("error in Downloading File from S3")
		}

		signVerified, _ := VerifyFileSimple(request["value"].(map[string]interface{})["signtext"].(string), fileName,
			request["value"].(map[string]interface{})["hashtext"].(string),
			request["value"].(map[string]interface{})["publickey"].(string))
		verifyResponse := VerifySignResposne{(signVerified == 0)}
		verifySimpleJSON, marshalErr := json.Marshal(verifyResponse)
		if marshalErr != nil {
			fmt.Println("error in VerifySignSimple Marshal:", marshalErr)
			return response, errors.New("Marshall of request failed")
		}
		response = Response{Message: string(verifySimpleJSON), OK: true}
	default:
		fmt.Println("Unknown Operation")
		return response, errors.New("Unkown Operation Requested")
	}
	return response, nil
}

func main() {
	lambda.Start(Handler)
}
