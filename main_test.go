package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandler(t *testing.T) {
	message := "Request to be signed"
	secretkey := "Fnx/FhcFnacMgo6Tw4mPSl+KBp09b+owys3/gF78hOpXZFDcFaFQ3y+0HXyDhghx1dVzJ/qJxIABMp9rsHt1ig=="
	publickey := "V2RQ3BWhUN8vtB18g4YIcdXVcyf6icSAATKfa7B7dYo="

	signRequestJSON := `{
		"operation": "SignSimple",
		"value": {"messagetext":"` + message + `",
		"secretkey":"` + secretkey + `"
		}}`

	signFileRequestJSON := `{
		"operation": "SignFileSimple",
		"value": { "s3bucket":"att3-data", "s3item":"user/test123add",
		"secretkey":"` + secretkey + `"
		}}`

	var request Request
	json.Unmarshal([]byte(signRequestJSON), &request)
	signResponse, _ := Handler(request)
	assert.Equal(t, true, signResponse.OK)

	rawValue := []byte(signResponse.Message)
	var signMessage SignResponse
	var verifyResponseMessage VerifySignResposne
	json.Unmarshal(rawValue, &signMessage)

	verifyRequestJSON := `{
			"operation": "VerifySignSimple",
			"value": {"signtext":"` + signMessage.SignText + `", "hashtext":"` + signMessage.HashText + `",
			"messagetext":"` + message + `" ,"publickey":"` + publickey + `"}}`
	json.Unmarshal([]byte(verifyRequestJSON), &request)
	verifyResponse, _ := Handler(request)
	json.Unmarshal([]byte(verifyResponse.Message), &verifyResponseMessage)
	assert.Equal(t, true, verifyResponseMessage.VerifiedStatus)

	json.Unmarshal([]byte(signFileRequestJSON), &request)
	signFileResponse, _ := Handler(request)
	assert.Equal(t, true, signFileResponse.OK)

	rawValueFileSign := []byte(signFileResponse.Message)
	json.Unmarshal(rawValueFileSign, &signMessage)

	verifyFileRequestJSON := `{
				"operation": "VerifyFileSimple",
				"value": {"signtext":"` + signMessage.SignText + `", "hashtext":"` + signMessage.HashText + `",
				"s3bucket":"att3-data", "s3item":"user/test123add","publickey":"` + publickey + `"}}`
	json.Unmarshal([]byte(verifyFileRequestJSON), &request)

	verifyFileResponse, _ := Handler(request)
	json.Unmarshal([]byte(verifyFileResponse.Message), &verifyResponseMessage)
	assert.Equal(t, true, verifyResponseMessage.VerifiedStatus)
}
