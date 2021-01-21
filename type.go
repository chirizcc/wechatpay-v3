package wechatpay

type QueryParam interface {
	Params(client *Client) map[string]interface{}
}

type BodyParam interface {
	Params(client *Client) BodyParam
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
