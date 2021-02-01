package wechatpay

type UploadResp struct {
	MediaId string `json:"media_id"`
}

func (u *UploadResp) IsSuccess() bool {
	return true
}
