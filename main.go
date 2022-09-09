package main

import (
	"github.com/joho/godotenv"
	"log"
	"voidchecker/apple"
	"voidchecker/google"
)

/*

https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests

-> Service Account 계정 정보(JSON 파일)로 Access Token 발급받는 과정을 저수준 HTTP/REST 이용해서 구현

https://developers.google.com/android-publisher/voided-purchases

-> 이 Access Token 이용해 무효화된(환불된) 영수증 받아와서 Redis 서버에 기록
구글에서는 최근 30일(기본값)까지 항목만 조회하는 것을 허용한다.

*/

func main() {
	log.Println("voidedreceiptchecker: Voided Receipt Checker")

	log.Println("voidedreceiptchecker: load .env file")
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}

	apple.CheckIos()
	google.CheckGoogle()
	google.CheckReceiptByPurchaseToken()
}
