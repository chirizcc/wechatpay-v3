package wechatpay

type Amount struct {
	Total    uint   `json:"total"`
	Currency string `json:"currency,omitempty"`
}

type Payer struct {
	Openid string `json:"openid"`
}

type TransactionsSceneInfo struct {
	PayerClientIp string `json:"payer_client_ip"`
	DeviceId      string `json:"device_id,omitempty"`
	StoreInfo     struct {
		Id       string `json:"id"`
		Name     string `json:"name,omitempty"`
		AreaCode string `json:"area_code,omitempty"`
		Address  string `json:"address,omitempty"`
	} `json:"store_info,omitempty"`
}

type TransactionsDetail struct {
	CostPrice   uint                     `json:"cost_price,omitempty"`
	InvoiceId   string                   `json:"invoice_id,omitempty"`
	GoodsDetail *TransactionsGoodsDetail `json:"goods_detail,omitempty"`
}

type TransactionsGoodsDetail struct {
	MerchantGoodsId  string `json:"merchant_goods_id"`
	WechatpayGoodsId string `json:"wechatpay_goods_id,omitempty"`
	GoodsName        string `json:"goods_name,omitempty"`
	Quantity         uint   `json:"quantity"`
	UnitPrice        uint   `json:"unit_price"`
}

type TransactionsJsapi struct {
	Appid       string                 `json:"appid"`
	Mchid       string                 `json:"mchid"`
	Description string                 `json:"description"`
	OutTradeNo  string                 `json:"out_trade_no"`
	TimeExpire  string                 `json:"time_expire,omitempty"`
	Attach      string                 `json:"attach,omitempty"`
	NotifyUrl   string                 `json:"notify_url"`
	GoodsTag    string                 `json:"goods_tag,omitempty"`
	Amount      *Amount                `json:"amount"`
	Payer       *Payer                 `json:"payer"`
	Detail      *TransactionsDetail    `json:"detail,omitempty"`
	SceneInfo   *TransactionsSceneInfo `json:"scene_info,omitempty"`
}

func (p *TransactionsJsapi) Params(client *Client) BodyParam {
	p.Mchid = client.mchId
	return p
}

type TransactionsResp struct {
	PrepayId string `json:"prepay_id"`
}

func (*TransactionsResp) IsSuccess() bool {
	return true
}

type CombineTransactionsSceneInfo struct {
	DeviceId      string                     `json:"device_id,omitempty"`
	PayerClientIp string                     `json:"payer_client_ip"`
	H5Info        *CombineTransactionsH5Info `json:"h5_info,omitempty"`
}

type CombineTransactionsH5Info struct {
	InfoType    string `json:"type"`
	AppName     string `json:"app_name,omitempty"`
	AppUrl      string `json:"app_url,omitempty"`
	BundleId    string `json:"bundle_id,omitempty"`
	PackageName string `json:"package_name,omitempty"`
}

type CombineTransactionsSettleInfo struct {
	ProfitSharing bool  `json:"profit_sharing,omitempty"`
	SubsidyAmount int64 `json:"subsidy_amount,omitempty"`
}

type CombineAmount struct {
	TotalAmount uint   `json:"total_amount"`
	Currency    string `json:"currency"`
}

type CombineTransactionsSubOrder struct {
	Mchid       string                         `json:"mchid"`
	Attach      string                         `json:"attach"`
	Amount      *CombineAmount                 `json:"amount"`
	OutTradeNo  string                         `json:"out_trade_no"`
	SubMchId    string                         `json:"sub_mchid"`
	Description string                         `json:"description"`
	SettleInfo  *CombineTransactionsSettleInfo `json:"settle_info,omitempty"`
}

type CombineTransactions struct {
	CombineAppid      string                         `json:"combine_appid"`
	CombineMchid      string                         `json:"combine_mchid"`
	CombineOutTradeNo string                         `json:"combine_out_trade_no"`
	SceneInfo         *CombineTransactionsSceneInfo  `json:"scene_info,omitempty"` // *注：该值在合单 H5 下单时为必填
	SubOrders         []*CombineTransactionsSubOrder `json:"sub_orders"`
	CombinePayerInfo  *Payer                         `json:"combine_payer_info"`
	TimeStart         string                         `json:"time_start,omitempty"`
	TimeExpire        string                         `json:"time_expire,omitempty"`
	NotifyUrl         string                         `json:"notify_url"`
}

func (p *CombineTransactions) Params(client *Client) BodyParam {
	p.CombineMchid = client.mchId

	for index := range p.SubOrders {
		p.SubOrders[index].Mchid = client.mchId
	}

	return p
}
