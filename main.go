package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	apiKey   = "" // Your walutomat API key
	urlBase  = "https://api.walutomat.pl"
	endpoint = "/api/v2.0.0/direct_fx/rates?currencyPair="
)

type CurrencyRate struct {
	Timestamp    time.Time
	CurrencyPair string
	BuyRate      float64
	SellRate     float64
}

func obtainExchangeRates(privateKey *rsa.PrivateKey) ([]CurrencyRate, error) {
	pairs := []string{"USDPLN", "GBPPLN", "CHFPLN", "EURPLN"}
	results := []CurrencyRate{}

	for _, pairName := range pairs {
		rate, err := getExchangeRate(pairName, privateKey)
		if err != nil {
			return nil, err
		}
		results = append(results, rate)
	}

	return results, nil
}

func getExchangeRate(pairName string, privateKey *rsa.PrivateKey) (CurrencyRate, error) {
	// Create signature
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature, err := signRequest(timestamp, endpoint+pairName, "", privateKey)
	if err != nil {
		fmt.Println("Error signing request:", err)
		return CurrencyRate{}, err
	}

	// Send the request
	client := &http.Client{}
	req, err := http.NewRequest("GET", urlBase+endpoint+pairName, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return CurrencyRate{}, err
	}

	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-API-Signature", signature)
	req.Header.Set("X-API-Timestamp", timestamp)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error executing request:", err)
		return CurrencyRate{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return CurrencyRate{}, err
	}

	type Response struct {
		Success bool `json:"success"`
		Result  struct {
			Ts           string  `json:"ts"`
			CurrencyPair string  `json:"currencyPair"`
			BuyRate      float64 `json:"buyRate,string"`
			SellRate     float64 `json:"sellRate,string"`
		} `json:"result"`
	}

	var respDecoded Response
	err = json.Unmarshal([]byte(body), &respDecoded)
	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return CurrencyRate{}, err
	}

	parsedTime, err := time.Parse(time.RFC3339, respDecoded.Result.Ts)
	if err != nil {
		fmt.Println("Error parsing timestamp:", err)
		return CurrencyRate{}, err
	}

	rate := CurrencyRate{
		Timestamp:    parsedTime,
		CurrencyPair: respDecoded.Result.CurrencyPair,
		BuyRate:      respDecoded.Result.BuyRate,
		SellRate:     respDecoded.Result.SellRate,
	}

	return rate, nil
}

func signRequest(timestamp, endpoint, body string, privateKey crypto.PrivateKey) (string, error) {
	signatureContent := timestamp + endpoint + body
	hashed := sha256.Sum256([]byte(signatureContent))

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, hashed[:])
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(signature), nil
	default:
		return "", errors.New("unsupported key type")
	}
}

func main() {
	key := []byte(`-----BEGIN RSA PRIVATE KEY-----
// Your private key contents / or provide through file
-----END RSA PRIVATE KEY-----`)

	decodedBlock, _ := pem.Decode(key)

	if decodedBlock == nil {
		fmt.Println("Unable to PEM decode.")
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(decodedBlock.Bytes)
	if err != nil {
		fmt.Println("Unable to parse PCKS1 private key:", err)
		return
	}

	rates, err := obtainExchangeRates(privateKey)

	if err != nil {
		fmt.Println(err)
		return
	}

	for _, rate := range rates {
		fmt.Println(rate)
	}

}
