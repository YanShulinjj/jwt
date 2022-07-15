/* ----------------------------------
*  @author suyame 2022-07-15 11:27:00
*  Crazy for Golang !!!
*  IDE: GoLand
*-----------------------------------*/

package service

import (
	"JWTdemo/internal"
	"JWTdemo/utils"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// 标记jwt object 的状态：存活还是到期
	ALIVE = 1 << iota
	DEAD
)

type JWTService struct {
	sync.RWMutex
	len         uint64
	header      internal.JwtHeader
	signature   internal.JwtSignature
	tokens      map[string]*internal.JWT
	hidden_func func(string, string) string
	// token 过期时的钩子函数, 类似存入token到磁盘
	hook_func func(...interface{})
}

func NewJWTService(alg string) *JWTService {
	js := &JWTService{
		tokens: make(map[string]*internal.JWT, 0),
	}
	js.Init(alg)
	js.Monitor()
	return js
}

func (js *JWTService) Init(alg string) {
	js.header = internal.JwtHeader{
		Alg: alg,
		Typ: "JWT",
	}
	js.signature = internal.JwtSignature{
		Screct: "my screct!",
	}
	if alg == "HS256" {
		js.hidden_func = utils.SHA256
	} else {
		js.hidden_func = utils.MD5
	}
}

func (js *JWTService) SetHookFunc(hook_func func(...interface{})) {
	js.hook_func = hook_func
}

// Add 颁发一个token
func (js *JWTService) Add(lifespan time.Duration) (string, error) {
	js.Lock()
	defer js.Unlock()
	js.len++
	jp := internal.JwtPayload{
		Jti: js.len,
		Iss: "suyame",
		Iat: time.Now(),
		Exp: time.Now().Add(lifespan),
	}
	jwt, err := internal.NewJWT(js.header, jp, js.signature, js.hidden_func)
	if err != nil {
		return "", err
	}
	jwt.Status = ALIVE
	token := jwt.String()
	js.tokens[token] = jwt
	return token, nil
}

// Check 判断token是否被篡改过
func (js *JWTService) Check(token string) bool {
	// 拿到尾部
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		fmt.Println("错误格式的token!")
		return false
	}
	headbase64, payldbase64, get := parts[0], parts[1], parts[2]
	headbyte := utils.Decode(headbase64)
	payldbyte := utils.Decode(payldbase64)

	secret := js.signature.Screct
	headbase64URL := utils.EncodeURL(headbyte)
	payldbase64URL := utils.EncodeURL(payldbyte)

	tail := headbase64URL + "." + payldbase64URL
	expect := js.hidden_func(tail, secret)

	return get == expect
}

// Auth 对token鉴权
func (js *JWTService) Auth(token string) bool {
	// 首先判断该token 是否被篡改过
	if ok := js.Check(token); !ok {
		fmt.Println("该token被篡改过！")
		return false
	}
	js.RLock()
	defer js.RUnlock()
	jwt, ok := js.tokens[token]
	if !ok {
		fmt.Println("无法识别的token！")
		return false
	}
	if jwt.Status == DEAD {
		fmt.Println("该token已经过期！")
		return false
	}
	// fmt.Println("token鉴权成功")
	return true
}

// Monitor 动态更新token状态
func (js *JWTService) Monitor() {
	// 遍历当前所有token
	// 并且找到最小的间隔时间
	interval := time.Duration(0)
	js.RLock()
	for _, jwt := range js.tokens {
		if jwt.Status == DEAD {
			continue
		}
		gap := jwt.ExpiredTime().Sub(time.Now())
		if gap <= 0 {
			/*** hook ****/
			if js.hook_func != nil {
				js.hook_func(jwt)
			}
			js.RUnlock()
			js.Lock()
			jwt.Status = DEAD
			// fmt.Printf("[Monitor] %s dead...\n", k)
			js.Unlock()
			js.RLock()
			continue
		}
		if interval == 0 || interval > gap {
			interval = gap
		}
	}
	js.RUnlock()
	if interval >= 0 {
		time.AfterFunc(interval, func() {
			js.Monitor()
		})
	}
}
