package unionpay5_1_0

import (
	"strings"
	"fmt"
	"io/ioutil"
	"net/url"
	"net/http"
	"time"
	"net"
	"encoding/base64"
	"sort"
)

func timeoutDialer(cTimeout time.Duration,
	rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(rwTimeout))
		return conn, nil
	}
}

func timeoutClient() *http.Client {
	connectTimeout := time.Duration(20 * time.Second)
	readWriteTimeout := time.Duration(30 * time.Second)
	return &http.Client{
		Transport: &http.Transport{
			Dial:                timeoutDialer(connectTimeout, readWriteTimeout),
			MaxIdleConnsPerHost: 200,
			DisableKeepAlives:   true,
		},
	}
}

// 发送post请求
func post(requrl string, request map[string]string) (interface{}, error) {
	println(requrl)
	c := timeoutClient()
	resp, err := c.Post(requrl, "application/x-www-form-urlencoded", strings.NewReader(Http_build_query(request)))
	if err != nil {
		return resp, err
	}
	if resp.StatusCode != 200 {
		return resp, fmt.Errorf("http request response StatusCode:%v", resp.StatusCode)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, err
	}
	var fields []string
	fields = strings.Split(string(data), "&")

	vals := url.Values{}
	for _, field := range fields {
		f := strings.SplitN(field, "=", 2)
		if len(f) >= 2 {
			key, val := f[0], f[1]
			vals.Set(key, val)
		}
	}
	fmt.Println("欧巴桑::", string(data), resp.StatusCode)
	fmt.Println("==============================================================================")
	//for k, v := range request {
	//	fmt.Println(k, "=", v)
	//}
	return Verify(vals)
}

// urlencode
func Http_build_query(params map[string]string) string {
	qs := url.Values{}
	for k, v := range params {
		qs.Add(k, v)
	}
	return qs.Encode()
}

// base64 加密
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// base64 解密
func base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

type mapSorter []sortItem

type sortItem struct {
	Key string      `json:"key"`
	Val interface{} `json:"val"`
}

func (ms mapSorter) Len() int {
	return len(ms)
}
func (ms mapSorter) Less(i, j int) bool {
	return ms[i].Key < ms[j].Key // 按键排序
}
func (ms mapSorter) Swap(i, j int) {
	ms[i], ms[j] = ms[j], ms[i]
}
func mapSortByKey(m map[string]string, step1, step2 string) string {
	ms := make(mapSorter, 0, len(m))

	for k, v := range m {
		ms = append(ms, sortItem{k, v})
	}
	sort.Sort(ms)
	s := []string{}
	for _, p := range ms {
		s = append(s, p.Key+step1+p.Val.(string))
	}
	return strings.Join(s, step2)
}