package wechatpay

// 支付 包括基础支付及合单支付

// TransactionsJsapi 基础支付 JSAPI 支付统一下单
func (c *Client) TransactionsJsapi(param *TransactionsJsapi) (*TransactionsResp, error) {
	result := &TransactionsResp{}
	err := c.DoRequest("POST", "/v3/pay/transactions/jsapi", param, result)
	return result, err
}

// CombineTransactionsJsapi 合单支付 JSAPI 下单
func (c *Client) CombineTransactionsJsapi(param *CombineTransactions) (*TransactionsResp, error) {
	result := &TransactionsResp{}
	err := c.DoRequest("POST", "/v3/combine-transactions/jsapi", param, result)
	return result, err
}
