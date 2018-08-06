package unionpay5_1_0

import (
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"golang.org/x/crypto/pkcs12"
	"fmt"
	"crypto/rand"
	"crypto/sha256"
	"crypto"
	"sort"
	"strings"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"paysvr/sdk/common"
	log "github.com/cihub/seelog"
)

// 根据银联获取到的PFX文件和密码来解析出里面包含的私钥(rsa)和证书(x509)
func ParserPfxToCert(path string, password string) (private *rsa.PrivateKey, cert *x509.Certificate, err error) {
	var pfxData []byte
	pfxData, err = ioutil.ReadFile(path)
	if err != nil {
		return
	}
	var priv interface{}
	privs, certs, err := pkcs12.DecodeAll(pfxData, password)
	if err != nil {
		return
	}
	cert = certs[0]
	priv = privs[0]
	private = priv.(*rsa.PrivateKey)
	return
}

// 根据文件名解析出证书
func ParseCertificateFromFile(path string) (cert *x509.Certificate, err error) {
	// Read the verify sign certification key
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = fmt.Errorf("bad key data: %s", "not PEM-encoded")
		return
	}
	if got, want := block.Type, "CERTIFICATE"; got != want {
		err = fmt.Errorf("unknown key type %q, want %q", got, want)
		return
	}

	// Decode the certification
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("bad private key: %s", err)
		return
	}
	return
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

// 参数排序
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

// base64 加密
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// base64 解密
func base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// sign 签名
func sign(request map[string]string) (string, error) {
	str := mapSortByKey(request, "=", "&")
	fmt.Println("============================================代签名排序串========================================================")
	fmt.Println(str)
	rng := rand.Reader
	hashed := sha256.Sum256([]byte(fmt.Sprintf("%x", sha256.Sum256([]byte(str)))))
	signer, err := rsa.SignPKCS1v15(rng, certData.Private, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64Encode(signer), nil
}

// 返回数据验签
func verify(vals url.Values) (res common.Request, err error) {
	var signature string
	var signPubKeyCert string
	kvs := map[string]string{}
	for k := range vals {
		if k == "signature" {
			signature = vals.Get(k)
			continue
		} else if k == "signPubKeyCert" {
			signPubKeyCert = vals.Get(k)
		}
		if vals.Get(k) == "" {
			continue
		}
		kvs[k] = vals.Get(k)
	}
	str := mapSortByKey(kvs, "=", "&")
	hashed := sha256.Sum256([]byte(fmt.Sprintf("%x", sha256.Sum256([]byte(str)))))
	var inSign []byte
	inSign, err = base64Decode(signature)
	if err != nil {
		return nil, fmt.Errorf("解析返回signature失败 %v", err)
	}

	//检查signPubKeyCert是否做过验证
	pub := redisMe.Get(signPubKeyCert)
	if pub == nil { //验证证书

		// Read the verify sign certification key
		pemData := []byte(signPubKeyCert)

		// Extract the PEM-encoded data block
		block, _ := pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("bad key data: %s", "not PEM-encoded")
		}
		if got, want := block.Type, "CERTIFICATE"; got != want {
			return nil, fmt.Errorf("unknown key type %q, want %q", got, want)
		}

		// Decode the certification
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("bad private key: %s", err)
		}


		//验证证书链
		roots := x509.NewCertPool()
		roots.AddCert(certData.RootCert)
		intermediateCerts := x509.NewCertPool()
		intermediateCerts.AddCert(certData.MiddleCert)
		intermediateCerts.AddCert(certData.RootCert)
		//链式向上验证证书
		//验证用户证书
		opts := x509.VerifyOptions{
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			Intermediates: intermediateCerts,
			Roots:         roots,
		}
		if _, err := cert.Verify(opts); err != nil {
			log.Error("failed to verify certificate::" + err.Error())
			return nil, fmt.Errorf("failed to verify certificate Chain::" + err.Error())
		}


		//验证证书是否属于银联
		UNIONPAY_CNNAME := "中国银联股份有限公司"
		cn := strings.Split(cert.Subject.CommonName, "@")[2]
		if UNIONPAY_CNNAME != cn {
			log.Error("证书不属于银联")
			return nil, fmt.Errorf("证书不属于银联")
		}

		pub = cert.PublicKey.(*rsa.PublicKey)

		//验证成功的证书加入到缓存里面
		redisMe.Set(signPubKeyCert, pub)

		log.Trace("验证成功的证书加入到缓存里面：", redisMe)

	}
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], inSign)
	if err != nil {
		log.Error("返回数据验签失败 ERR:", err)
		return nil, fmt.Errorf("返回数据验签失败 ERR:%v", err)
	}
	return kvs, nil
}