package apple

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type ClaimSet struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Bid string `json:"bid"`
}

// AuthKeyFromFile loads a .p8 certificate from a local file and returns a
// *ecdsa.PrivateKey.
func AuthKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return AuthKeyFromBytes(bytes)
}

// AuthKeyFromBytes loads a .p8 certificate from an in memory byte array and
// returns an *ecdsa.PrivateKey.
func AuthKeyFromBytes(bytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		panic("block null")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	if pk, ok := key.(*ecdsa.PrivateKey); ok {
		return pk, nil
	}
	panic("not ECDSA")
}

func CheckIos() {
	packageName := os.Getenv("VOIDCHECKER_IOS_PACKAGE_NAME")
	kid := os.Getenv("VOIDCHECKER_APPLE_KEY_ID")
	issuerId := os.Getenv("VOIDCHECKER_APPLE_ISSUER_ID")
	privateFilePath := os.Getenv("VOIDCHECKER_APPLE_KEY_PATH")

	const Alg = "ES256"

	headerBytes, err := json.Marshal(JwtHeader{Alg: Alg, Typ: "JWT", Kid: kid})
	if err != nil {
		panic(err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	now := time.Now()

	claimSet := ClaimSet{
		Aud: "appstoreconnect-v1",
		Iss: issuerId,
		Iat: now.Unix(),
		Exp: now.Unix() + int64((20 * time.Minute).Seconds()), // 최대 허용 시간이 20분이다.
		Bid: packageName,
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

	ecdsaKey, err := AuthKeyFromFile(privateFilePath)
	if err != nil {
		panic(err)
	}

	method := jwt.GetSigningMethod(Alg)

	signature, err := method.Sign(baseStrForSigEncoded, ecdsaKey)
	if err != nil {
		panic(err)
	}

	jwtEncoded := baseStrForSigEncoded + "." + signature
	log.Println(jwtEncoded)

	testTransactionId := os.Getenv("VOIDCHECKER_IOS_TEST_TRANSACTION_ID")
	refundedGetUrl := fmt.Sprintf("https://api.storekit.itunes.apple.com/inApps/v2/refund/lookup/%s", testTransactionId)
	//refundedGetUrl := "https://api.appstoreconnect.apple.com/v1/apps"
	req , err := http.NewRequest("GET", refundedGetUrl, nil)
	req.Header.Set("Authorization", "Bearer " + jwtEncoded)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	str := string(respBody)
	log.Println(str)
}
