package wechatpay

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
)

// CertificateDriver 证书中控存放驱动
type CertificateDriver interface {
	// 	get 根据序列号获取证书
	get(serialNumber string) (*x509.Certificate, error)

	// set 根据序列号设置证书
	set(serialNumber string, pemData []byte) error

	// count 获取证书数量
	count() int
}

// MemoryDriver 内存驱动，使用 sync.Map 存放
type MemoryDriver struct {
	certs sync.Map
}

func (m *MemoryDriver) get(serialNumber string) (*x509.Certificate, error) {
	cert, ok := m.certs.Load(serialNumber)
	if !ok {
		return nil, errors.New("cert not exists")
	}

	c, ok := cert.(*x509.Certificate)
	if !ok {
		return nil, errors.New("get cert error")
	}

	return c, nil
}

func (m *MemoryDriver) set(serialNumber string, pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	m.certs.Store(serialNumber, cert)
	return nil
}

func (m *MemoryDriver) count() int {
	count := 0

	m.certs.Range(func(k, v interface{}) bool {
		count++
		return true
	})

	return count
}
