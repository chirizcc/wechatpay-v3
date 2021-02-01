package wechatpay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type loggedRoundTripper struct {
	rt     http.RoundTripper
	logger logger
}

func (c *loggedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	startTime := time.Now()
	response, err := c.rt.RoundTrip(request)
	duration := time.Since(startTime)

	if c.logger != nil {
		c.logger.record(request, response, err, duration)
	}
	return response, err
}

func newLoggedTransport(rt http.RoundTripper, log logger) http.RoundTripper {
	return &loggedRoundTripper{rt: rt, logger: log}
}

// logger 日志接口，可自己实现日志记录
type logger interface {
	// record 记录日志
	record(req *http.Request, resp *http.Response, err error, duration time.Duration)
}

// FileLogger 文件日志
type FileLogger struct {
	file *os.File
}

func (f *FileLogger) record(req *http.Request, resp *http.Response, err error, duration time.Duration) {
	reqHeadersData, err := json.Marshal(req.Header)
	if err != nil {
		return
	}

	var reqData []byte
	if req.Body != nil {
		reqBody, err := req.GetBody()
		if err != nil {
			return
		}

		reqData, err = ioutil.ReadAll(reqBody)
		if err != nil {
			return
		}
	}

	respHeadersData, err := json.Marshal(resp.Header)
	if err != nil {
		return
	}

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	resp.Body.Close()
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(respData)) // resp.Body 无法多次读取，利用该方式重新写入 resp.Body 用于记录日志

	_, _ = f.file.WriteString(fmt.Sprintf(
		"[%s] req_method: %s; req_url: %s; req_headers: %s; req_params: %s; resp_status: %d; resp_headers: %s; resp_data: %s; duration: %d; err: %v \n",
		time.Now().Format("2006-01-02 15:04:05"),
		req.Method,
		resp.Request.URL,
		string(reqHeadersData),
		string(reqData),
		resp.StatusCode,
		string(respHeadersData),
		string(respData),
		duration,
		err,
	))
}

// NewFileLogger 获取 FileLogger 实例
func NewFileLogger(file *os.File) *FileLogger {
	return &FileLogger{file: file}
}
