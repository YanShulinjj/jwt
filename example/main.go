/* ----------------------------------
*  @author suyame 2022-07-15 10:41:00
*  Crazy for Golang !!!
*  IDE: GoLand
*-----------------------------------*/

package main

import (
	"JWTdemo/service"
	"fmt"
	"time"
)

func Print(a ...interface{}) {
	fmt.Println(a)
}

func main() {
	js := service.NewJWTService("MD5")
	js.SetHookFunc(Print)
	t1, _ := js.Add(3000)
	t2, _ := js.Add(time.Second)
	fmt.Println(t1)
	fmt.Println(t2)
	for js.Auth(t2) {
		// js.Auth(t1)
	}

}
