package wechatpay

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

type Central struct {
	client *Client
	driver CertificateDriver
	skip   bool
}

func newCentral(client *Client, driver CertificateDriver, pemDataArr [][]byte) (*Central, error) {
	c := &Central{
		client: client,
		driver: driver,
		skip:   false,
	}

	for _, pemData := range pemDataArr {
		if err := c.loadCert(pemData); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *Central) start() {
	// 初次执行无任何平台证书时跳过验签，不推荐在生产环境使用
	if c.driver.Count() == 0 {
		c.skip = true
	}

	// 开启定时获取微信平台证书
	go func() {
		// 创建一个计时器
		timeTickerChan := time.Tick(time.Hour * 12)
		for {
			func() {
				defer func() {
					c.skip = false
				}()
				c.updateCerts()
			}()
			<-timeTickerChan
		}
	}()
}

func (c *Central) getCert(serialNumber string) (*x509.Certificate, error) {
	return c.driver.Get(serialNumber)
}

func (c *Central) skipValidate() bool {
	return c.skip
}

func (c *Central) loadCert(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	serialNumber := strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes()))

	if err = c.driver.Set(serialNumber, pemData); err != nil {
		return err
	}

	return nil
}

func (c *Central) updateCerts() {
	result := &CertificatesResult{}
	if err := c.client.DoRequest("GET", "/v3/certificates", result); err != nil {
		// @TODO 错误处理
		return
	}

	for _, v := range result.Data {
		pemData, err := c.client.AesDecrypt(v.EncryptCertificate.Ciphertext, v.EncryptCertificate.Nonce, v.EncryptCertificate.AssociatedData)
		if err != nil {
			// @TODO 错误处理
			continue
		}

		if err = c.driver.Set(v.SerialNo, pemData); err != nil {
			// @TODO 错误处理
			continue
		}
	}
}
