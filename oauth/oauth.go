package oauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/rockpunch/discogs-api/util"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	baseUrl         = "https://api.discogs.com/oauth"
	requestTokenUrl = baseUrl + "/request_token"
	authorizeUrl    = baseUrl + "/authorize"
	accessTokenUrl  = baseUrl + "/access_token"
)

type Token struct {
	Type        string `json:"token_type"`
	AccessToken string `json:"access_token"`
}

type OAuth struct {
	ConsumerKey       string
	ConsumerSecret    string
	CallbackUrl       string
	Verifier          string
	SignatureMethod   string
	Token             string
	TokenSecret       string
	CallbackConfirmed string
	ContentType       string
	UserAgent         string
	AOAToken          Token
}

func (oAuth *OAuth) OAuthAuthorize() string {
	return authorizeUrl + "?oauth_token=" + oAuth.Token
}

func (oAuth *OAuth) RequestToken() error {
	v := url.Values{}
	v.Set("oauth_callback", oAuth.CallbackUrl)

	req, err := http.NewRequest(http.MethodGet, requestTokenUrl, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", oAuth.UserAgent)
	req.Header.Add("Authorization", reqTokenAuthHeader(*oAuth, v))

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response status=%d, body=%s", resp.StatusCode, string(bodyBytes))
	}

	defer resp.Body.Close()

	m, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return err
	}

	// set result
	oAuth.Token = m.Get("oauth_token")
	oAuth.TokenSecret = m.Get("oauth_token_secret")
	oAuth.CallbackConfirmed = m.Get("oauth_callback_confirmed")
	return nil
}

func (oAuth *OAuth) AccessToken(verifier string) error {
	v := url.Values{}
	v.Set("oauth_verifier", verifier)

	req, err := http.NewRequest("POST", accessTokenUrl, strings.NewReader(util.NormalizeParam(v)))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", oAuth.ContentType)
	req.Header.Add("User-Agent", oAuth.UserAgent)
	req.Header.Add("Authorization", accTokenAuthHeader(*oAuth, verifier, v))

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response status=%d, message=%s", resp.StatusCode, string(bodyBytes))
	}

	m, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return err
	}

	// set result
	oAuth.Token = m.Get("oauth_token")
	oAuth.TokenSecret = m.Get("oauth_token_secret")
	return nil
}

func accTokenAuthHeader(oAuth OAuth, verifier string, v url.Values) string {

	v.Set("oauth_nonce", util.Nonce())
	v.Set("oauth_timestamp", strconv.FormatInt(time.Now().UnixNano(), 10))
	v.Set("oauth_consumer_key", oAuth.ConsumerKey)
	v.Set("oauth_signature", oAuth.ConsumerSecret + "&" + oAuth.TokenSecret)
	v.Set("oauth_signature_method", oAuth.SignatureMethod)
	v.Set("oauth_token", oAuth.Token)
	v.Set("oauth_verifier", verifier)

	var oauthParams []string
	for k := range v {
		// get only oauth_ params to set them into authorization string
		if strings.HasPrefix(k, "oauth_") {
			oauthParams = append(oauthParams, k+`="`+url.QueryEscape(v.Get(k))+`"`)
		}
	}
	return `OAuth ` + strings.Join(oauthParams, ", ")
}

func reqTokenAuthHeader(oAuth OAuth, v url.Values) string {
	v.Set("oauth_nonce", util.Nonce())
	v.Set("oauth_timestamp", strconv.FormatInt(time.Now().UnixNano(), 10))
	v.Set("oauth_consumer_key", oAuth.ConsumerKey)
	v.Set("oauth_signature", oAuth.ConsumerSecret+"&")
	v.Set("oauth_signature_method", oAuth.SignatureMethod)

	if oAuth.Token != "" {
		v.Set("oauth_token", oAuth.Token)
	}

	var oauthParams []string
	for k := range v {
		// get only oauth_ params to set them into authorization string
		if strings.HasPrefix(k, "oauth_") && k != "oauth_verifier" {
			oauthParams = append(oauthParams, k+`="`+url.QueryEscape(v.Get(k))+`"`)
		}
	}

	return `OAuth ` + strings.Join(oauthParams, ", ")
}

func signSignature(signBaseStr string, consumerSecret string) string {
	signingKey := []byte(consumerSecret)
	mac := hmac.New(sha1.New, signingKey)
	mac.Write([]byte(signBaseStr))
	signedSig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return signedSig
}
