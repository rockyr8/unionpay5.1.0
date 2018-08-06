package unionpay5_1_0

import (
	"strings"
	"fmt"
	"io/ioutil"
	"net/url"
	"net/http"
	"time"
	"net"
	"crypto/rsa"
	"crypto/x509"
	"sync"
)


var certData *Cert

// 证书信息结构体
type Cert struct {
	// 私钥 签名使用 700000000000001_acp.pfx
	Private *rsa.PrivateKey
	// 证书 与私钥为一套 700000000000001_acp.pfx
	Cert *x509.Certificate
	// 签名证书ID 700000000000001_acp.pfx
	CertId string
	// 中级证书 acp_test_middle.cer
	MiddleCert *x509.Certificate
	// 根证书 acp_test_root.cer
	RootCert *x509.Certificate
}

var redisMe *Cache

//测试用 的缓存
type Cache struct {
	Data map[string]*rsa.PublicKey
	sync.RWMutex
}

//获取value
func (d *Cache) Get(k string) *rsa.PublicKey {
	d.RLock()
	defer d.RUnlock()
	return d.Data[k]
}

//设置value
func (d *Cache) Set(k string, v *rsa.PublicKey) {
	d.Lock()
	defer d.Unlock()
	d.Data[k] = v
}

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
	//for k, v := range request {
	//	fmt.Println(k, "=", v)
	//}
	return verify(vals)
}

// urlencode
func Http_build_query(params map[string]string) string {
	qs := url.Values{}
	for k, v := range params {
		qs.Add(k, v)
	}
	return qs.Encode()
}

