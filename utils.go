package wechatpay

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"unsafe"
)

// getNonce 获取随机字符串
func getNonce() string {
	l := 32

	var container string
	var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	b := bytes.NewBufferString(str)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0; i < l; i++ {
		randomInt, _ := rand.Int(rand.Reader, bigInt)
		container += string(str[randomInt.Int64()])
	}
	return container
}

// byte2String 将 byte 数组转换为字符串
func byte2String(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
