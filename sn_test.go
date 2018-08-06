package unionpay5_1_0

import (
	"fmt"
	"testing"
	"crypto/rsa"
	"time"
)

func TestSn(t *testing.T) {
	initConfig()
}

func initConfig() {

	//初始化证书路径
	var pfxPath, pfxPWD, middleCertPath, rootCertPath string
	certData = &Cert{}

	//签名
	pfxPath = ""
	pfxPWD = ""
	//中级证书
	middleCertPath = ""
	//根证书
	rootCertPath = ""
	var err error
	//签名证书
	certData.Private, certData.Cert, err = ParserPfxToCert(pfxPath, pfxPWD)
	if err != nil {
		panic("签名证书初始化失败::" + err.Error())
	}
	//证书ID
	certData.CertId = fmt.Sprintf("%v", certData.Cert.SerialNumber)

	//中级证书
	certData.MiddleCert, err = ParseCertificateFromFile(middleCertPath)
	if err != nil {
		panic("银联中级证书初始化失败::" + err.Error())
	}
	//根证书
	certData.RootCert, err = ParseCertificateFromFile(rootCertPath)
	if err != nil {
		panic("银联根证书初始化失败::" + err.Error())
	}

	//初始化缓存
	redisMe = &Cache{}
	redisMe.Data = make(map[string]*rsa.PublicKey)

	//初始化缓存
	redisMe = &Cache{}
	redisMe.Data = make(map[string]*rsa.PublicKey)

}

func getSN(){
	var request = make(map[string]string)
	request["merId"] = ""
	request["version"] = "5.1.0"
	request["encoding"] = "UTF-8"
	request["certId"] = certData.CertId
	request["signMethod"] = "01"  // RSA
	request["txnType"] = "01"     // 消费
	request["txnSubType"] = "01"  // 自助消费
	request["bizType"] = "000201" // 网关支付
	request["channelType"] = "08" // 移动渠道
	request["accessType"] = "0"
	request["backUrl"] = ""
	request["orderId"] = ""
	request["currencyCode"] = "156" // 人民币
	request["txnAmt"] = "0.01"
	now := time.Now()
	request["txnTime"] = now.Format("20060102150405")
	request["signature"], _ = sign(request)

	fmt.Println("======================================签名信息==============================================================")
	fmt.Println(request["signature"])

	url := "https://gateway.95516.com/gateway/api/appTransReq.do"

	post(url, request)
}
