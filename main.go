package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

func main() {
	wrapper.SetCtx(
		"ai-baiducloud-security",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
		wrapper.ProcessRequestBodyBy(onHttpRequestBody),
		wrapper.ProcessResponseHeadersBy(onHttpResponseHeaders),
		wrapper.ProcessResponseBodyBy(onHttpResponseBody),
	)
}

const (
	OpenAIResponseFormat       = `{"id": "%s","object":"chat.completion","model":"ai-baiducloud-security","choices":[{"index":0,"message":{"role":"assistant","content":"%s"},"logprobs":null,"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`
	OpenAIStreamResponseChunk  = `data:{"id":"%s","object":"chat.completion.chunk","model":"ai-baiducloud-security","choices":[{"index":0,"delta":{"role":"assistant","content":"%s"},"logprobs":null,"finish_reason":null}]}`
	OpenAIStreamResponseEnd    = `data:{"id":"%s","object":"chat.completion.chunk","model":"ai-baiducloud-security","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`
	OpenAIStreamResponseFormat = OpenAIStreamResponseChunk + "\n\n" + OpenAIStreamResponseEnd + "\n\n" + `data: [DONE]`

	DefaultRequestCheckService       = "/rcs/llm/input/analyze"
	DefaultResponseCheckService      = "/rcs/llm/output/analyze"
	DefaultRequestJsonPath           = "messages.@reverse.0.content"
	DefaultResponseJsonPath          = "choices.0.message.content"
	DefaultStreamingResponseJsonPath = "choices.0.delta.content"
	DefaultDenyCode                  = 200
	DefaultDenyMessage               = "很抱歉，我无法回答您的问题"
	DefaultTimeout                   = 5000

	LengthLimit = 1800

	ActionRedlineAnswer = 1
	ActionSafeAnswer    = 2
	ActionDefaultAnswer = 3
	ActionDeny          = 6
)

type Response struct {
	RequestId string `json:"request_id"`
	RetCode   string `json:"ret_code"`
	RetMsg    string `json:"ret_msg"`
	RetData   struct {
		Score      float64 `json:"score"`
		HitType    string  `json:"hitType"`
		SubHitType string  `json:"subHitType"`
		SafeChat   string  `json:"safeChat"`
		Action     int     `json:"action"`
		LangType   string  `json:"langType"`
		IsSafe     int     `json:"isSafe"`
		Redline    struct {
			Answer string  `json:"answer"`
			Score  float64 `json:"score"`
		} `json:"redline"`
		DefaultAnswer string `json:"defaultAnswer"`
	} `json:"ret_data"`
}

type AISecurityConfig struct {
	client                        wrapper.HttpClient
	Host                          string
	ak                            string
	sk                            string
	checkRequest                  bool
	requestCheckService           string
	requestContentJsonPath        string
	checkResponse                 bool
	responseCheckService          string
	responseContentJsonPath       string
	responseStreamContentJsonPath string
	denyCode                      int64
	denyMessage                   string
	protocolOriginal              bool
	timeout                       uint32
	metrics                       map[string]proxywasm.MetricCounter
	MockResp                      string
}

func (config *AISecurityConfig) incrementCounter(metricName string, inc uint64) {
	counter, ok := config.metrics[metricName]
	if !ok {
		counter = proxywasm.DefineCounterMetric(metricName)
		config.metrics[metricName] = counter
	}
	counter.Increment(inc)
}

func parseConfig(json gjson.Result, config *AISecurityConfig, log wrapper.Log) error {
	serviceName := json.Get("serviceName").String()
	servicePort := json.Get("servicePort").Int()
	serviceHost := json.Get("serviceHost").String()
	if serviceName == "" || servicePort == 0 || serviceHost == "" {
		return errors.New("invalid service config")
	}
	config.Host = serviceHost
	config.ak = json.Get("accessKey").String()
	config.sk = json.Get("secretKey").String()
	if config.ak == "" || config.sk == "" {
		return errors.New("invalid AK/SK config")
	}
	config.checkRequest = json.Get("checkRequest").Bool()
	config.checkResponse = json.Get("checkResponse").Bool()
	config.protocolOriginal = json.Get("protocol").String() == "original"
	config.denyMessage = json.Get("denyMessage").String()
	if obj := json.Get("denyCode"); obj.Exists() {
		config.denyCode = obj.Int()
	} else {
		config.denyCode = DefaultDenyCode
	}
	if obj := json.Get("requestCheckService"); obj.Exists() {
		config.requestCheckService = obj.String()
	} else {
		config.requestCheckService = DefaultRequestCheckService
	}
	if obj := json.Get("responseCheckService"); obj.Exists() {
		config.responseCheckService = obj.String()
	} else {
		config.responseCheckService = DefaultResponseCheckService
	}
	if obj := json.Get("requestContentJsonPath"); obj.Exists() {
		config.requestContentJsonPath = obj.String()
	} else {
		config.requestContentJsonPath = DefaultRequestJsonPath
	}
	if obj := json.Get("responseContentJsonPath"); obj.Exists() {
		config.responseContentJsonPath = obj.String()
	} else {
		config.responseContentJsonPath = DefaultResponseJsonPath
	}
	if obj := json.Get("responseStreamContentJsonPath"); obj.Exists() {
		config.responseStreamContentJsonPath = obj.String()
	} else {
		config.responseStreamContentJsonPath = DefaultStreamingResponseJsonPath
	}
	if obj := json.Get("timeout"); obj.Exists() {
		config.timeout = uint32(obj.Int())
	} else {
		config.timeout = DefaultTimeout
	}
	config.MockResp = json.Get("mockResp").String()
	config.client = wrapper.NewClusterClient(wrapper.FQDNCluster{
		FQDN: serviceName,
		Port: servicePort,
		Host: serviceHost,
	})
	config.metrics = make(map[string]proxywasm.MetricCounter)
	return nil
}

func generateRandomID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 29)
	for i := range b {
		b[i] = charset[mrand.Intn(len(charset))]
	}
	return "chatcmpl-" + string(b)
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config AISecurityConfig, log wrapper.Log) types.Action {
	if !config.checkRequest {
		log.Debugf("request checking is disabled")
		ctx.DontReadRequestBody()
	}
	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config AISecurityConfig, body []byte, log wrapper.Log) types.Action {
	log.Debugf("checking request body...")
	startTime := time.Now().UnixMilli()
	content := gjson.GetBytes(body, config.requestContentJsonPath).String()
	log.Debugf("Raw request content is: %s", content)
	if len(content) == 0 {
		log.Info("request content is empty. skip")
		return types.ActionContinue
	}
	contentIndex := 0
	var singleCall func()
	callback := func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		log.Info(string(responseBody))
		if statusCode != http.StatusOK || gjson.GetBytes(responseBody, "ret_code").String() != "0" {
			proxywasm.ResumeHttpRequest()
			return
		}
		var response Response
		err := json.Unmarshal(responseBody, &response)
		if err != nil {
			log.Error("failed to unmarshal aliyun content security response at request phase")
			proxywasm.ResumeHttpRequest()
			return
		}
		if response.RetData.IsSafe == 1 {
			if contentIndex >= len(content) {
				endTime := time.Now().UnixMilli()
				ctx.SetUserAttribute("safecheck_request_rt", endTime-startTime)
				ctx.SetUserAttribute("safecheck_status", "request pass")
				ctx.WriteUserAttributeToLogWithKey(wrapper.AILogKey)
				proxywasm.ResumeHttpRequest()
			} else {
				singleCall()
			}
			return
		}
		denyMessage := DefaultDenyMessage
		if config.denyMessage != "" {
			denyMessage = config.denyMessage
		} else if response.RetData.Action == ActionRedlineAnswer && response.RetData.Redline.Answer != "" {
			denyMessage = response.RetData.Redline.Answer
		} else if response.RetData.Action == ActionSafeAnswer && response.RetData.SafeChat != "" {
			denyMessage = response.RetData.SafeChat
		} else if response.RetData.Action == ActionDefaultAnswer && response.RetData.DefaultAnswer != "" {
			denyMessage = response.RetData.DefaultAnswer
		} else if response.RetData.Action == ActionDeny {

		}
		marshalledDenyMessage := marshalStr(denyMessage, log)
		if config.protocolOriginal {
			proxywasm.SendHttpResponse(uint32(config.denyCode), [][2]string{{"content-type", "application/json"}}, []byte(marshalledDenyMessage), -1)
		} else if gjson.GetBytes(body, "stream").Bool() {
			randomID := generateRandomID()
			jsonData := []byte(fmt.Sprintf(OpenAIStreamResponseFormat, randomID, marshalledDenyMessage, randomID))
			proxywasm.SendHttpResponse(uint32(config.denyCode), [][2]string{{"content-type", "text/event-stream;charset=UTF-8"}}, jsonData, -1)
		} else {
			randomID := generateRandomID()
			jsonData := []byte(fmt.Sprintf(OpenAIResponseFormat, randomID, marshalledDenyMessage))
			proxywasm.SendHttpResponse(uint32(config.denyCode), [][2]string{{"content-type", "application/json"}}, jsonData, -1)
		}
		ctx.DontReadResponseBody()
		config.incrementCounter("ai_sec_request_deny", 1)
		endTime := time.Now().UnixMilli()
		ctx.SetUserAttribute("safecheck_request_rt", endTime-startTime)
		ctx.SetUserAttribute("safecheck_status", "reqeust deny")
		ctx.SetUserAttribute("safecheck_riskAction", response.RetData.Action)
		ctx.WriteUserAttributeToLogWithKey(wrapper.AILogKey)
	}
	singleCall = func() {
		var nextContentIndex int
		if contentIndex+LengthLimit >= len([]rune(content)) {
			nextContentIndex = len(content)
		} else {
			nextContentIndex = contentIndex + LengthLimit
		}
		contentPiece := content[contentIndex:nextContentIndex]
		contentIndex = nextContentIndex
		log.Debugf("current content piece: %s", contentPiece)

		method := "POST"
		path := config.requestCheckService
		headers := map[string]string{
			"host":         config.Host,
			"content-type": "application/json; charset=utf-8",
			"x-bce-date":   getCanonicalTime(0),
		}
		var credentials = BceCredentials{
			AccessKeyID:     config.ak,
			SecretAccessKey: config.sk,
		}
		signature := sign(credentials, method, path, headers, nil, time.Now().Unix(), 18000, map[string]bool{
			"host":       true,
			"x-bce-date": true,
		})
		jsonBody, _ := json.Marshal(map[string]interface{}{
			"query":     contentPiece,
			"historyQA": []interface{}{},
		})
		Header := [][2]string{
			//{"Host", headers["host"]},
			{"Content-Type", headers["content-type"]},
			{"x-bce-date", headers["x-bce-date"]},
			{"Authorization", signature},
		}
		log.Debugf("Header is: %v", Header)
		err := config.client.Post(path, Header, jsonBody, callback, config.timeout)
		if err != nil {
			log.Errorf("failed call the safe check service: %v", err)
			proxywasm.ResumeHttpRequest()
		}
	}
	singleCall()
	return types.ActionPause
}

func onHttpResponseHeaders(ctx wrapper.HttpContext, config AISecurityConfig, log wrapper.Log) types.Action {
	if !config.checkResponse {
		log.Debugf("response checking is disabled")
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}
	statusCode, _ := proxywasm.GetHttpResponseHeader(":status")
	if statusCode != "200" {
		log.Debugf("response is not 200, skip response body check")
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}
	log.Debugf("response is 200, response body check")
	return types.HeaderStopIteration
}

func onHttpResponseBody(ctx wrapper.HttpContext, config AISecurityConfig, body []byte, log wrapper.Log) types.Action {
	log.Debugf("checking response body : %s , %d", string(body), len(body))
	startTime := time.Now().UnixMilli()
	contentType, _ := proxywasm.GetHttpResponseHeader("content-type")
	isStreamingResponse := strings.Contains(contentType, "event-stream")
	var content string
	if isStreamingResponse {
		content = extractMessageFromStreamingBody(body, config.responseStreamContentJsonPath)
	} else {
		content = gjson.GetBytes(body, config.responseContentJsonPath).String()
	}
	if config.MockResp != "" {
		content = config.MockResp
	}
	log.Debugf("Raw response content is: %s , %d", content, len(content))
	if len(content) == 0 {
		log.Info("response content is empty. skip")
		return types.ActionContinue
	}
	randomID := generateRandomID()
	contentIndex := 0
	var singleCall func()
	callback := func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		log.Info(string(responseBody))
		if statusCode != http.StatusOK || gjson.GetBytes(responseBody, "ret_code").String() != "0" {
			proxywasm.ResumeHttpResponse()
			return
		}
		var response Response
		err := json.Unmarshal(responseBody, &response)
		if err != nil {
			log.Error("failed to unmarshal aliyun content security response at request phase")
			proxywasm.ResumeHttpResponse()
			return
		}
		if response.RetData.IsSafe == 1 {
			if contentIndex >= len(content) {
				endTime := time.Now().UnixMilli()
				ctx.SetUserAttribute("safecheck_request_rt", endTime-startTime)
				ctx.SetUserAttribute("safecheck_status", "response pass")
				ctx.WriteUserAttributeToLogWithKey(wrapper.AILogKey)
				proxywasm.ResumeHttpResponse()
			} else {
				singleCall()
			}
			return
		}
		denyMessage := DefaultDenyMessage
		if config.denyMessage != "" {
			denyMessage = config.denyMessage
		} else if response.RetData.Action == ActionRedlineAnswer && response.RetData.Redline.Answer != "" {
			denyMessage = response.RetData.Redline.Answer
		} else if response.RetData.Action == ActionSafeAnswer && response.RetData.SafeChat != "" {
			denyMessage = response.RetData.SafeChat
		} else if response.RetData.Action == ActionDefaultAnswer && response.RetData.DefaultAnswer != "" {
			denyMessage = response.RetData.DefaultAnswer
		} else if response.RetData.Action == ActionDeny {

		}
		marshalledDenyMessage := marshalStr(denyMessage, log)
		if config.protocolOriginal {
			proxywasm.SendHttpResponse(uint32(config.denyCode), [][2]string{{"content-type", "application/json"}}, []byte(marshalledDenyMessage), -1)
		} else if gjson.GetBytes(body, "stream").Bool() {
			jsonData := []byte(fmt.Sprintf(OpenAIStreamResponseFormat, randomID, marshalledDenyMessage, randomID))
			proxywasm.SendHttpResponse(uint32(config.denyCode), [][2]string{{"content-type", "text/event-stream;charset=UTF-8"}}, jsonData, -1)
		} else {
			jsonData := []byte(fmt.Sprintf(OpenAIResponseFormat, randomID, marshalledDenyMessage))
			err := proxywasm.SendHttpResponse(uint32(http.StatusOK), [][2]string{{"content-type", "application/json"}}, jsonData, -1)
			if err != nil {
				log.Errorf("failed to send http response: %v", err)
				proxywasm.ResumeHttpResponse()
			}
		}
		log.Debugf("marshalledDenyMessage is: %v", marshalledDenyMessage)
		config.incrementCounter("ai_sec_response_deny", 1)
		endTime := time.Now().UnixMilli()
		ctx.SetUserAttribute("safecheck_response_rt", endTime-startTime)
		ctx.SetUserAttribute("safecheck_status", "response deny")
		ctx.SetUserAttribute("safecheck_riskAction", response.RetData.Action)
		ctx.WriteUserAttributeToLogWithKey(wrapper.AILogKey)
	}
	singleCall = func() {
		var nextContentIndex int
		if contentIndex+LengthLimit >= len(content) {
			nextContentIndex = len(content)
		} else {
			nextContentIndex = contentIndex + LengthLimit
		}
		contentPiece := content[contentIndex:nextContentIndex]
		contentIndex = nextContentIndex
		log.Debugf("current content piece: %s", contentPiece)
		method := "POST"
		path := config.responseCheckService
		headers := map[string]string{
			"host":         config.Host,
			"content-type": "application/json; charset=utf-8",
			"x-bce-date":   getCanonicalTime(0),
		}
		var credentials = BceCredentials{
			AccessKeyID:     config.ak,
			SecretAccessKey: config.sk,
		}
		signature := sign(credentials, method, path, headers, nil, time.Now().Unix(), 18000, map[string]bool{
			"host":       true,
			"x-bce-date": true,
		})
		jsonBody, _ := json.Marshal(map[string]interface{}{
			"reqId":   randomID,
			"content": contentPiece,
			"isFirst": 1,
		})
		Header := [][2]string{
			//{"Host", headers["host"]},
			{"Content-Type", headers["content-type"]},
			{"x-bce-date", headers["x-bce-date"]},
			{"Authorization", signature},
		}
		log.Debugf("Header is: %v", Header)
		err := config.client.Post(path, Header, jsonBody, callback, config.timeout)
		if err != nil {
			log.Errorf("failed call the safe check service: %v", err)
			proxywasm.ResumeHttpResponse()
		}

	}
	singleCall()
	return types.ActionPause
}

func extractMessageFromStreamingBody(data []byte, jsonPath string) string {
	chunks := bytes.Split(bytes.TrimSpace(data), []byte("\n\n"))
	strChunks := []string{}
	for _, chunk := range chunks {
		// Example: "choices":[{"index":0,"delta":{"role":"assistant","content":"%s"},"logprobs":null,"finish_reason":null}]
		strChunks = append(strChunks, gjson.GetBytes(chunk, jsonPath).String())
	}
	return strings.Join(strChunks, "")
}

func marshalStr(raw string, log wrapper.Log) string {
	helper := map[string]string{
		"placeholder": raw,
	}
	marshalledHelper, _ := json.Marshal(helper)
	marshalledRaw := gjson.GetBytes(marshalledHelper, "placeholder").Raw
	if len(marshalledRaw) >= 2 {
		return marshalledRaw[1 : len(marshalledRaw)-1]
	} else {
		log.Errorf("failed to marshal json string, raw string is: %s", raw)
		return ""
	}
}

// 常量定义
const (
	Authorization   = "authorization"
	BCEPrefix       = "x-bce-"
	DefaultEncoding = "UTF-8"
)

// BceCredentials 认证信息结构体
type BceCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// 保留字符集
var reservedCharSet = map[rune]struct{}{
	'a': {}, 'b': {}, 'c': {}, 'd': {}, 'e': {}, 'f': {}, 'g': {}, 'h': {}, 'i': {}, 'j': {},
	'k': {}, 'l': {}, 'm': {}, 'n': {}, 'o': {}, 'p': {}, 'q': {}, 'r': {}, 's': {}, 't': {},
	'u': {}, 'v': {}, 'w': {}, 'x': {}, 'y': {}, 'z': {}, 'A': {}, 'B': {}, 'C': {}, 'D': {},
	'E': {}, 'F': {}, 'G': {}, 'H': {}, 'I': {}, 'J': {}, 'K': {}, 'L': {}, 'M': {}, 'N': {},
	'O': {}, 'P': {}, 'Q': {}, 'R': {}, 'S': {}, 'T': {}, 'U': {}, 'V': {}, 'W': {}, 'X': {},
	'Y': {}, 'Z': {}, '0': {}, '1': {}, '2': {}, '3': {}, '4': {}, '5': {}, '6': {}, '7': {},
	'8': {}, '9': {}, '.': {}, '~': {}, '-': {}, '_': {},
}

// 字符串规范化
func normalizeString(s string, encodeSlash bool) string {
	var buf bytes.Buffer
	for _, r := range s {
		if _, ok := reservedCharSet[r]; ok || (!encodeSlash && r == '/') {
			buf.WriteRune(r)
		} else {
			buf.WriteString(fmt.Sprintf("%%%02X", r))
		}
	}
	return buf.String()
}

// 获取规范时间
func getCanonicalTime(timestamp int64) string {
	var t time.Time
	if timestamp == 0 {
		t = time.Now().UTC()
	} else {
		t = time.Unix(timestamp, 0).UTC()
	}
	return t.Format("2006-01-02T15:04:05Z")
}

// 生成规范URI
func getCanonicalUri(path string) string {
	return normalizeString(path, false)
}

// 生成规范查询字符串
func getCanonicalQueryString(params map[string]string) string {
	var keys []string
	for k := range params {
		if strings.ToLower(k) != Authorization {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s",
			normalizeString(k, false),
			normalizeString(params[k], false)))
	}
	return strings.Join(parts, "&")
}

// 生成规范头
func getCanonicalHeaders(headers map[string]string, headersToSign map[string]bool) string {
	defaultHeaders := map[string]bool{
		"host":           true,
		"content-md5":    true,
		"content-length": true,
		"content-type":   true,
	}

	var headerList []string
	for k, v := range headers {
		key := strings.ToLower(strings.TrimSpace(k))
		value := strings.TrimSpace(v)

		if headersToSign == nil {
			if defaultHeaders[key] || strings.HasPrefix(key, BCEPrefix) {
				headerList = append(headerList, fmt.Sprintf("%s:%s",
					normalizeString(key, false),
					normalizeString(value, false)))
			}
		} else {
			if headersToSign[key] || strings.HasPrefix(key, BCEPrefix) {
				headerList = append(headerList, fmt.Sprintf("%s:%s",
					normalizeString(key, false),
					normalizeString(value, false)))
			}
		}
	}
	sort.Strings(headerList)
	return strings.Join(headerList, "\n")
}

// 签名生成
func sign(creds BceCredentials, method, path string, headers map[string]string,
	params map[string]string, timestamp int64, expiration int, headersToSign map[string]bool) string {

	// 生成签名密钥
	canonicalTime := getCanonicalTime(timestamp)
	signKeyInfo := fmt.Sprintf("bce-auth-v1/%s/%s/%d",
		creds.AccessKeyID, canonicalTime, expiration)

	h := hmac.New(sha256.New, []byte(creds.SecretAccessKey))
	h.Write([]byte(signKeyInfo))
	signKey := hex.EncodeToString(h.Sum(nil))

	// 生成签名要素
	canonicalUri := getCanonicalUri(path)
	canonicalQuery := getCanonicalQueryString(params)
	canonicalHeaders := getCanonicalHeaders(headers, headersToSign)

	// 生成签名字符串
	stringToSign := strings.Join([]string{
		method,
		canonicalUri,
		canonicalQuery,
		canonicalHeaders,
	}, "\n")

	h = hmac.New(sha256.New, []byte(signKey))
	h.Write([]byte(stringToSign))
	signature := hex.EncodeToString(h.Sum(nil))

	// 构造最终签名
	signedHeaders := "host"
	if headersToSign != nil {
		var headers []string
		for k := range headersToSign {
			headers = append(headers, k)
		}
		sort.Strings(headers)
		signedHeaders = strings.Join(headers, ";")
	}
	return fmt.Sprintf("%s/%s/%s", signKeyInfo, signedHeaders, signature)
}
