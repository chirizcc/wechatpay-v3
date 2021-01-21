package wechatpay

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
)

type CertificateDriver interface {
	Get(serialNumber string) (*x509.Certificate, error)
	Set(serialNumber string, pemData []byte) error
	Count() int
}

type MemoryDriver struct {
	certs sync.Map
}

func (m *MemoryDriver) Get(serialNumber string) (*x509.Certificate, error) {
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

func (m *MemoryDriver) Set(serialNumber string, pemData []byte) error {
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

func (m *MemoryDriver) Count() int {
	count := 0

	m.certs.Range(func(k, v interface{}) bool {
		count++
		return true
	})

	return count
}
