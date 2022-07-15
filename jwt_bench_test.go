/* ----------------------------------
*  @author suyame 2022-07-15 19:57:00
*  Crazy for Golang !!!
*  IDE: GoLand
*-----------------------------------*/

package JWTdemo

import (
	"JWTdemo/service"
	"sync"
	"testing"
	"time"
)

func BenchmarkJWT(b *testing.B) {
	// 新建一个JWT, MD5是支持的加密算法
	jwt := service.NewJWTService("MD5")
	_, err := jwt.Add(time.Second)
	if err != nil {
		b.Errorf("NewJWT err, %v", err)
	}
	wg := sync.WaitGroup{}

	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			token, _ := jwt.Add(time.Duration(j) * time.Microsecond)
			if !jwt.Auth(token) {
				b.Errorf("鉴权失败！")
			}
		}(i)
	}
	wg.Wait()
}
