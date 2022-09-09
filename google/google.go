package google

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/go-redis/redis/v8"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type ServiceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenUri    string `json:"token_uri"`
}

type GoogleAccessToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type ClaimSet struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
}

type VoidedPurchaseResponse struct {
	VoidedPurchases []VoidedPurchase `json:"voidedPurchases"`
}

type VoidedPurchase struct {
	PurchaseToken      string `json:"purchaseToken"`
	PurchaseTimeMillis string `json:"purchaseTimeMillis"`
	VoidedTimeMillis   string `json:"voidedTimeMillis"`
	OrderId            string `json:"orderId"`
	VoidedSource       int    `json:"voidedSource"`
	VoidedReason       int    `json:"voidedReason"`
	Kind               string `json:"kind"`
}

var ctx = context.Background()

var rdb = redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "", // no password set
	DB:       0,  // use default DB
})

// CheckReceiptByPurchaseToken 테스트 용도: Purchase Token으로 Order ID 알아내기
func CheckReceiptByPurchaseToken() {
	packageName := os.Getenv("VOIDCHECKER_ANDROID_PACKAGE_NAME")
	credPath := os.Getenv("VOIDCHECKER_SERVICE_ACCOUNT_CRED_PATH")

	cachedAccessToken, err := getCachedAccessToken(packageName, credPath)
	if err != nil {
		panic(err)
	}

	productId := os.Getenv("VOIDCHECKER_ANDROID_TEST_PRODUCT_ID")
	purchaseToken := os.Getenv("VOIDCHECKER_ANDROID_TEST_PURCHASE_TOKEN")
	getUrl := fmt.Sprintf("https://www.googleapis.com/androidpublisher/v3/applications/%v/purchases/products/%v/tokens/%v?access_token=%v", packageName, productId, purchaseToken, cachedAccessToken)

	resp, err := http.Get(getUrl)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(resp.Body)

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	str := string(respBody)
	println("==================================")
	println(str)
	println("==================================")
}

func CheckGoogle() {
	packageName := os.Getenv("VOIDCHECKER_ANDROID_PACKAGE_NAME")
	credPath := os.Getenv("VOIDCHECKER_SERVICE_ACCOUNT_CRED_PATH")

	cachedAccessToken, err := getCachedAccessToken(packageName, credPath)
	if err != nil {
		panic(err)
	}

	voidedGetUrl := fmt.Sprintf("https://www.googleapis.com/androidpublisher/v3/applications/%s/purchases/voidedpurchases?access_token=%s", packageName, cachedAccessToken)

	resp, err := http.Get(voidedGetUrl)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(resp.Body)

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	str := string(respBody)
	println(str)

	var voidedPurchaseResponse VoidedPurchaseResponse
	err = json.Unmarshal(respBody, &voidedPurchaseResponse)
	if err != nil {
		panic(err)
	}

	voidedPurchasesHashKey := fmt.Sprintf("voidedreceiptchecker:%s:voidedPurchases", packageName)

	for _, purchase := range voidedPurchaseResponse.VoidedPurchases {
		purchaseStr, err := json.Marshal(purchase)
		if err != nil {
			panic(err)
		}

		_, err = rdb.HSet(ctx, voidedPurchasesHashKey, purchase.PurchaseToken, purchaseStr).Result()
		if err != nil {
			panic(err)
		}
	}
}

func getCachedAccessToken(packageName string, credPath string) (string, error) {
	cachedAccessTokenKey := fmt.Sprintf("voidedreceiptchecker:%s:cachedAccessTokenKey", packageName)

	cachedAccessToken, err := rdb.Get(ctx, cachedAccessTokenKey).Result()
	if err == redis.Nil {
		err = nil // 이건 에러가 아니다.
		googleAccessToken, err := getNewGoogleAccessToken(credPath)
		if err != nil {
			panic(err)
		}
		cachedAccessToken = googleAccessToken.AccessToken

		_, err = rdb.Set(ctx, cachedAccessTokenKey, cachedAccessToken, time.Duration(googleAccessToken.ExpiresIn)*time.Second).Result()
		if err != nil {
			panic(err)
		}
	} else if err != nil {
		panic(err)
	}
	return cachedAccessToken, err
}

func getNewGoogleAccessToken(credPath string) (GoogleAccessToken, error) {
	headerBytes, err := json.Marshal(JwtHeader{Alg: "RS256", Typ: "JWT"})
	if err != nil {
		panic(err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	credStr, err := ioutil.ReadFile(credPath)
	if err != nil {
		panic(err)
	}

	var serviceAccount ServiceAccount
	err = json.Unmarshal(credStr, &serviceAccount)
	if err != nil {
		panic(err)
	}

	log.Println(headerEncoded)
	log.Println(serviceAccount.ClientEmail)

	now := time.Now()

	const scope = "https://www.googleapis.com/auth/androidpublisher"

	claimSet := ClaimSet{
		Aud:   serviceAccount.TokenUri,
		Iss:   serviceAccount.ClientEmail,
		Iat:   now.Unix(),
		Exp:   now.Unix() + int64(time.Hour.Seconds()),
		Scope: scope,
	}

	claimSetBytes, err := json.Marshal(claimSet)
	if err != nil {
		panic(err)
	}

	log.Println(string(claimSetBytes))

	claimSetEncoded := base64.RawURLEncoding.EncodeToString(claimSetBytes)
	log.Println(claimSetEncoded)

	baseStrForSigEncoded := headerEncoded + "." + claimSetEncoded
	log.Println(baseStrForSigEncoded)

	h := sha256.New()
	h.Write([]byte(baseStrForSigEncoded))
	d := h.Sum(nil)

	block, _ := pem.Decode([]byte(serviceAccount.PrivateKey))
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	key := parseResult.(*rsa.PrivateKey)

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d)
	if err != nil {
		panic(err)
	}

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signatureBytes)
	log.Println(signatureEncoded)

	jwt := baseStrForSigEncoded + "." + signatureEncoded
	log.Println(jwt)

	const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	resp, err := http.PostForm(serviceAccount.TokenUri, url.Values{"grant_type": {grantType}, "assertion": {jwt}})
	if err != nil {
		panic(err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(resp.Body)

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	str := string(respBody)
	println(str)

	var googleAccessToken GoogleAccessToken
	err = json.Unmarshal(respBody, &googleAccessToken)
	if err != nil {
		panic(err)
	}
	return googleAccessToken, err
}

