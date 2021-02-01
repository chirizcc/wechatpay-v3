package wechatpay

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const schema = "WECHATPAY2-SHA256-RSA2048"

const baseUrl = "https://api.mch.weixin.qq.com"

type Client struct {
	mchId  string // 商户号
	apiKey []byte // APIv3 密钥

	platformCertCentral *Central // 微信支付平台证书中控

	merchantPrivateKey   *rsa.PrivateKey // 商户私钥
	merchantSerialNumber string          // 商户证书序列号

	httpClient http.Client
}

// New 获取新实例
func New(mchId string, apiKey string, logger logger) (*Client, error) {
	client := &Client{}
	client.mchId = mchId
	client.apiKey = []byte(apiKey)

	httpClient := http.Client{
		Transport: newLoggedTransport(http.DefaultTransport, logger),
	}

	client.httpClient = httpClient

	return client, nil
}

// LoadCertCentral 加载微信证书中控
func (c *Client) LoadCertCentral(driver CertificateDriver, pemDataArr [][]byte) error {
	if c.merchantPrivateKey == nil || c.merchantSerialNumber == "" { // 需先加载商户私钥
		return errors.New("please perform LoadMerchantPrivateKey")
	}

	central, err := newCentral(c, driver, pemDataArr)
	if err != nil {
		return err
	}

	c.platformCertCentral = central
	c.platformCertCentral.start()

	return nil
}

// LoadMerchantPrivateKeyFromFile 加载商户私钥
func (c *Client) LoadMerchantPrivateKeyFromFile(filePath string, serialNumber string) error {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	return c.LoadMerchantPrivateKey(b, serialNumber)
}

// LoadMerchantPrivateKey 加载商户私钥
func (c *Client) LoadMerchantPrivateKey(pemData []byte, serialNumber string) error {
	if serialNumber == "" {
		return errors.New("merchant serial number is empty")
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PRIVATE KEY" {
		return errors.New("failed to decode PEM block containing private key")
	}

	pri, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	privateKey, ok := pri.(*rsa.PrivateKey)
	if !ok {
		return errors.New("pri is not PrivateKey")
	}

	c.merchantPrivateKey = privateKey
	c.merchantSerialNumber = serialNumber

	return nil
}

// DoRequest 发送请求
func (c *Client) DoRequest(method string, apiUri string, vs ...interface{}) error {
	var (
		err           error
		query         = make(url.Values)
		body          []byte
		appendHeaders = make(map[string]string)
		result        Result
		fileParam     *FileParam
	)

	for _, v := range vs {
		switch vv := v.(type) {
		case QueryParam:
			for key, value := range vv.Params(c) {
				query.Add(key, fmt.Sprintf("%v", value))
			}
		case BodyParam:
			body, err = json.Marshal(vv.Params(c))
			if err != nil {
				return nil
			}
		case *FileParam:
			body = vv.meta()
			fileParam = vv
		case Result:
			result = vv
		}
	}

	queryStr := query.Encode()
	if queryStr != "" {
		if strings.IndexByte(apiUri, '?') == -1 {
			apiUri = apiUri + "?" + queryStr
		} else {
			apiUri = apiUri + "&" + queryStr
		}
	}

	uri, err := url.Parse(fmt.Sprintf("%s%s", baseUrl, apiUri))
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	if fileParam != nil {
		writer := multipart.NewWriter(buf)

		err = writer.WriteField("meta", byte2String(body))
		if err != nil {
			return err
		}

		formFile, err := writer.CreateFormFile("file", fileParam.fileName)
		if err != nil {
			return err
		}

		_, err = formFile.Write(fileParam.fileData)
		if err != nil {
			return err
		}

		_ = writer.Close()

		appendHeaders["Content-Type"] = writer.FormDataContentType()
	} else if len(body) > 0 {
		buf = bytes.NewBuffer(body)

		appendHeaders["Content-Type"] = "application/json"
	}

	req, err := http.NewRequest(method, uri.String(), buf)
	if err != nil {
		return err
	}

	for key, value := range appendHeaders {
		req.Header.Add(key, value)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", schema, c.getToken(method, uri, body)))

	req.Close = true

	resp, err := c.httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// 接口错误处理
	if resp.StatusCode != 200 {
		errResult := &ErrorResult{}
		err = json.Unmarshal(data, errResult)
		if err != nil {
			return err
		}

		return errors.New(fmt.Sprintf("request error code: %s; msg: %s", errResult.Code, errResult.Message))
	}

	// 验签
	if !c.platformCertCentral.skipValidate() && !c.validate(
		resp.Header.Get("Wechatpay-Timestamp"),
		resp.Header.Get("Wechatpay-Nonce"),
		resp.Header.Get("Wechatpay-Serial"),
		resp.Header.Get("Wechatpay-Signature"),
		data,
	) {
		return errors.New("validate sign failed")
	}

	if result != nil {
		err = json.Unmarshal(data, result)
		if err != nil {
			return err
		}
	}

	return nil
}

// AesDecrypt 解密
func (c *Client) AesDecrypt(crypted string, nonce string, additionalData string) ([]byte, error) {
	s, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(c.apiKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, []byte(nonce), s, []byte(additionalData))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// sign 签名
func (c *Client) sign(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	encryptedData, err := rsa.SignPKCS1v15(rand.Reader, c.merchantPrivateKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(encryptedData)
}

// getToken
func (c *Client) getToken(method string, uri *url.URL, body []byte) string {
	nonce := getNonce()
	timestamp := time.Now().Unix()

	message := c.buildMessage(method, uri.RequestURI(), timestamp, nonce, body)

	sign := c.sign(message)

	return fmt.Sprintf(
		`mchid="%s",nonce_str="%s",timestamp="%d",serial_no="%s",signature="%s"`,
		c.mchId,
		nonce,
		timestamp,
		c.merchantSerialNumber,
		sign,
	)
}

// validate 验签
func (c *Client) validate(timestamp string, nonce string, serial string, sign string, body []byte) bool {
	message := c.buildMessage(timestamp, nonce, body)

	cert, err := c.platformCertCentral.getCert(serial)
	if err != nil {
		return false
	}

	s, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false
	}

	hash := sha256.New()
	hash.Write(message)
	if err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash.Sum(nil), s); err == nil {
		return true
	}

	return false
}

// buildMessage
func (c *Client) buildMessage(fields ...interface{}) []byte {
	var buffer bytes.Buffer

	for _, item := range fields {
		switch field := item.(type) {
		case string:
			buffer.WriteString(field)
		case []byte:
			buffer.Write(field)
		case int64:
			buffer.WriteString(strconv.FormatInt(field, 10))
		case int:
			buffer.WriteString(strconv.Itoa(field))
		}

		buffer.WriteString("\n")
	}

	return buffer.Bytes()
}
