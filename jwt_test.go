/* ----------------------------------
*  @author suyame 2022-07-15 19:35:00
*  Crazy for Golang !!!
*  IDE: GoLand
*-----------------------------------*/

package JWTdemo

import (
	"testing"
	"time"
)
import "JWTdemo/service"

func TestNewJWT(t *testing.T) {
	// 新建一个JWT, SHA256 不是支持的加密算法
	jwt := service.NewJWTService("SHA256")
	_, err := jwt.Add(time.Second)
	if err == nil {
		t.Errorf("NewJWT err, sha256 should not support!")
	}
	// 新建一个JWT, MD5是支持的加密算法
	jwt = service.NewJWTService("MD5")
	_, err = jwt.Add(time.Second)
	if err != nil {
		t.Errorf("NewJWT err, %v", err)
	}
}

func TestAddToken(t *testing.T) {
	// 新建一个JWT, MD5是支持的加密算法
	jwt := service.NewJWTService("MD5")
	token, err := jwt.Add(2 * time.Second)
	if err != nil {
		t.Errorf("NewJWT err, %v", err)
	}
	time.Sleep(time.Second)
	if expect, get := true, jwt.Auth(token); expect != get {
		t.Error("Auth err, no expired token failed!\n")
	}
	token, err = jwt.Add(time.Second)
	time.Sleep(time.Second)
	if expect, get := false, jwt.Auth(token); expect != get {
		t.Error("Auth err, expired token failed!\n")
	}
}
