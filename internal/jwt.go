/* ----------------------------------
*  @author suyame 2022-07-15 10:41:00
*  Crazy for Golang !!!
*  IDE: GoLand
*-----------------------------------*/

package internal

import (
	"JWTdemo/utils"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"time"
)

type EncryType func(string, string) string
type JwtHeader struct {
	Alg string `json:"alg" validate:"required,oneof=HS256 MD5"`
	Typ string `json:"typ" validate:"required,oneof=JWT"`
}

// jwtPayload jwt主体部分
// iss：发行人
// exp：到期时间
// sub：主题
// aud：用户
// nbf：在此之前不可用
// iat：发布时间
// jti：JWT ID用于标识该JWT
type JwtPayload struct {
	Iss string    `json:"iss"`
	Exp time.Time `json:"exp"`
	Sub string    `json:"sub"`
	Aud string    `json:"aud"`
	Nbf time.Time `json:"nbf"`
	Iat time.Time `json:"iat"`
	Jti uint64    `json:"jti"`
}

type JwtSignature struct {
	Screct string `json:"screct"`
}
type JWT struct {
	header      JwtHeader    `json:"header"`
	payload     JwtPayload   `json:"payload"`
	signature   JwtSignature `json:"signature"`
	hidden_func EncryType
	Status      uint8
}

// NewJWT 新建jwt对象并对齐进行验证
func NewJWT(header JwtHeader, jp JwtPayload, sign JwtSignature, hidden EncryType) (*JWT, error) {
	jwt := &JWT{
		header:      header,
		payload:     jp,
		signature:   sign,
		hidden_func: hidden,
	}
	// 判断是否符合
	err := jwt.validate()
	if err != nil {
		return nil, err
	}
	return jwt, nil
}

// validate 验证jwt指定字段是否符合规范
func (jwt *JWT) validate() (err error) {
	validate := validator.New()
	err = validate.Struct(jwt.header)
	return
}

// String 将obeject转换成string
func (jwt *JWT) String() string {
	headByte, err := json.Marshal(jwt.header)
	if err != nil {
		fmt.Errorf("header Marshal err: %v \n", err)
	}
	headBase64 := utils.Encode(headByte)
	payldByte, err := json.Marshal(jwt.payload)
	if err != nil {
		fmt.Errorf("payload Marshal err: %v \n", err)
	}
	payldBase64 := utils.Encode(payldByte)
	secret := jwt.signature.Screct

	headBase64URL := utils.EncodeURL(headByte)
	payldBase64URL := utils.EncodeURL(payldByte)

	tail := headBase64URL + "." + payldBase64URL
	jwtString := headBase64 + "." + payldBase64 + "." + jwt.hidden_func(tail, secret)
	return jwtString
}

// ExpiredTime 获得此jwt的过期时间
func (jwt *JWT) ExpiredTime() time.Time {
	return jwt.payload.Exp
}
