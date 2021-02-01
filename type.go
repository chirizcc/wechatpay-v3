package wechatpay

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type QueryParam interface {
	Params(client *Client) map[string]interface{}
}

type BodyParam interface {
	Params(client *Client) BodyParam
}

func NewFileParam(file *os.File) (*FileParam, error) {
	fileData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return &FileParam{
		fileName: file.Name(),
		fileData: fileData,
	}, nil
}

type FileParam struct {
	fileName string
	fileData []byte
}

func (f *FileParam) meta() []byte {
	h := sha256.New()
	h.Write(f.fileData)

	meta := map[string]string{
		"filename": f.fileName,
		"sha256":   fmt.Sprintf("%x", h.Sum(nil)),
	}

	metaByte, err := json.Marshal(meta)
	if err != nil {
		return metaByte
	}

	return metaByte
}

type Result interface {
	IsSuccess() bool
}

type CertificatesResult struct {
	Data []struct {
		EffectiveTime      string `json:"effective_time"`
		EncryptCertificate struct {
			Algorithm      string `json:"algorithm"`
			AssociatedData string `json:"associated_data"`
			Ciphertext     string `json:"ciphertext"`
			Nonce          string `json:"nonce"`
		} `json:"encrypt_certificate"`
		ExpireTime string `json:"expire_time"`
		SerialNo   string `json:"serial_no"`
	} `json:"data"`
}

func (r *CertificatesResult) IsSuccess() bool {
	return true
}

type ErrorResult struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
