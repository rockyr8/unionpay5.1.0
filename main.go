package unionpay5_1_0

import "fmt"

func main(){

}

func getSN(){
	request := make(map[string]string)
	request["version"] = "5.1.0"                                                            //版本号
	request["encoding"] = "UTF-8"                                                           //编码方式
	request["txnType"] = "01"                                                               //交易类型
	request["txnSubType"] = "01"                                                            //交易子类
	request["bizType"] = "000201"                                                           //业务类型
	request["signMethod"] = "01"                                                            //签名方法 固定01
	request["channelType"] = "08"                                                           //渠道类型
	request["accessType"] = "0"                                                             //接入类型
	request["backUrl"] = "http://222.222.222.222:8080/demo/api_05_app/BackRcvResponse.aspx" //后台通知地址
	request["currencyCode"] = "156"                                                         //交易币种

	request["merId"] = "777290058110048"        //商户号，请改自己的测试商户号，此处默认取demo演示页面传递的参数
	request["orderId"] = "20180715170846419"    //商户订单号，8-32位数字字母，不能含“-”或“_”
	request["txnTime"] = "20180715170846"       //订单发送时间，格式为YYYYMMDDhhmmss，取北京时间，此处默认取demo演示页面传递的参数，参考取法： DateTime.Now.ToString("yyyyMMddHHmmss")
	request["txnAmt"] = fmt.Sprintf("%d", 1000) //交易金额，单位分
	request["signature"], _ = Sign(request)
	//request["signature"] = `0KsO6+98l+T5iW9gbTMRg3alH8nSdKWNWRg0vUoZqD6DJyXF1wjG/CrFUrX6qWms19KFnS356eSXOavtdn8CtGj2X7YdNZ/cRARqDmQer1hAjtg40dv0dPKZrTa0I0+Wagp+0g5VtvfcuBKCyNTKIRlnr5ZdFic0GnPqz7jozxSjjySKQ7vhqeOg7D4MnYYWBpnO97U/4AYEsC4WZpVaHb9loPD35lM1uVvmLLy9IEsnGBPFlTknjQef4b5yb8gpyNyEALqp4wv2qEzZ8blw9uloB84uaCh6vScUS2DOx5z1uzX51F5IuULDnIkKDQzyboxmIIi6fkj5ryFic1MrPQ==`

	request["certId"] = certData.CertId // "68759663125" //证书ID

	println(request["signature"])
}