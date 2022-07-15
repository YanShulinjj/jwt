/* ----------------------------------
*  @author suyame 2022-07-15 14:59:00
*  Crazy for Golang !!!
*  IDE: GoLand
*-----------------------------------*/

package utils

import (
	"encoding/base64"
	"fmt"
)

// Encode Base64 Standard Encoding
func Encode(data []byte) string {
	sEnc := base64.StdEncoding.EncodeToString(data)
	return sEnc
}

// Decode is Base64 Standard Decoding
func Decode(sEnc string) []byte {
	sDec, err := base64.StdEncoding.DecodeString(sEnc)
	if err != nil {
		fmt.Printf("Error decoding string: %s ", err.Error())
		return nil
	}
	return sDec
}

// Encode Base64 URL Encoding
func EncodeURL(data []byte) string {
	sEnc := base64.URLEncoding.EncodeToString(data)
	return sEnc
}

// Decode is Base64 URL Decoding
func DecodeURL(sEnc string) []byte {
	sDec, err := base64.URLEncoding.DecodeString(sEnc)
	if err != nil {
		fmt.Printf("Error decoding string: %s ", err.Error())
		return nil
	}
	return sDec
}
