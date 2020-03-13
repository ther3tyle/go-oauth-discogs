package main

import "C"
import (
	"flag"
	"github.com/go-playground/validator"
	"github.com/rockpunch/discogs-api/api/client/discogs"
	"github.com/rockpunch/discogs-api/util"
)

var (
	key             string
	secret          string
	callback        string
	useragent       string
	signatureMethod string
	Client          discogs.Discogs
)

func init() {
	flag.StringVar(&key, "k", "Consumer-Consumer-Key", "")
	flag.StringVar(&secret, "s", "Your-Consumer-Secret", "")
	flag.StringVar(&useragent, "u", "Your-User-Agent", "")
	flag.StringVar(&callback, "c", "Your-CallBack-Url", "")
	flag.StringVar(&signatureMethod, "sigaturemethod", "PLAINTEXT", "Set the plain text value")
}

func main() {
	flag.Parse()
	validate()
	setClient()

}

func setClient() {
	Client.ConsumerKey = key
	Client.ConsumerSecret = secret
	Client.UserAgent = useragent
	Client.CallbackUrl = callback
	Client.SignatureMethod = signatureMethod
}

func validate() {
	validation := validator.New()
	s := []string{key, secret, useragent}
	for _, v := range s {
		err := validation.Var(v, "required")
		util.HandleError(err)
	}
}
