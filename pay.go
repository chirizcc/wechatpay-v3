package wechatpay

func (c *Client) TransactionsJsapi(param *TransactionsJsapi) (*TransactionsResp, error) {
	result := &TransactionsResp{}
	err := c.DoRequest("POST", "/v3/pay/transactions/jsapi", param, result)
	return result, err
}

func (c *Client) CombineTransactionsJsapi(param *CombineTransactions) (*TransactionsResp, error) {
	result := &TransactionsResp{}
	err := c.DoRequest("POST", "/v3/combine-transactions/jsapi", param, result)
	return result, err
}
