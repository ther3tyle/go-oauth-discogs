package discogs

import (
	"fmt"
	"github.com/rockpunch/discogs-api/oauth"
	"github.com/rockpunch/discogs-api/util"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Discogs struct {
	oauth.OAuth
}

func (dc *Discogs) GetIdentity() {
	reqUri := fmt.Sprintf("https://api.discogs.com/oauth/identity")
	req, err := http.NewRequest(http.MethodGet, reqUri, nil)
	util.HandleError(err)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", dc.UserAgent)
	req.Header.Add("Authorization", dc.authHeader())

	fmt.Println("authHeader:", dc.authHeader())

	client := http.Client{Timeout:time.Second}
	resp, err := client.Do(req)
	util.HandleError(err)

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	fmt.Println(resp.Status)
	util.HandleError(err)

	defer log.Fatalln(resp.Body.Close())

	fmt.Println(string(bodyBytes))
}




func (dc *Discogs) authHeader() string {
	v := url.Values{}
	v.Add("oauth_consumer_key", dc.ConsumerKey)
	v.Add("oauth_token", dc.Token)
	v.Add("oauth_signature", fmt.Sprintf("%s&%s", dc.ConsumerSecret, dc.TokenSecret))
	v.Add("oauth_signature_method", dc.SignatureMethod)
	v.Add("oauth_timestamp", strconv.FormatInt(time.Now().UnixNano(), 10))
	v.Add("oauth_nonce", util.Nonce())

	var oauthParams []string
	for k := range v {
		// get only oauth_ params to set them into authorization string
		if strings.HasPrefix(k, "oauth_") {
			oauthParams = append(oauthParams, k+`="`+url.QueryEscape(v.Get(k))+`"`)
		}
	}

	return `OAuth ` + strings.Join(oauthParams, ", ")
}

