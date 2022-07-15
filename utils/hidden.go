/* ----------------------------------
*  @author suyame 2022-07-15 15:15:00
*  Crazy for Golang !!!
*  IDE: GoLand
*-----------------------------------*/

package utils

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func SHA256(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func MD5(str, secret string) string {
	b := []byte(str)
	s := []byte(secret)
	h := md5.New()
	h.Write(s) // 先写盐值
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
