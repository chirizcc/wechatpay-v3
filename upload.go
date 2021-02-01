package wechatpay

func (c *Client) MediaUpload(param *FileParam) (*UploadResp, error) {
	result := &UploadResp{}
	err := c.DoRequest("POST", "/v3/merchant/media/upload", param, result)
	return result, err
}
