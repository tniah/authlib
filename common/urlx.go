package common

import (
	"fmt"
	"net/http"
	"net/url"
)

const HeaderLocation = "Location"

func AddParamsToURI(uri string, params map[string]interface{}) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}

	q := u.Query()
	for k, v := range params {
		q.Set(k, fmt.Sprint(v))
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func Redirect(rw http.ResponseWriter, uri string, params map[string]interface{}) error {
	location, err := AddParamsToURI(uri, params)
	if err != nil {
		return err
	}

	rw.Header().Set(HeaderLocation, location)
	rw.WriteHeader(http.StatusFound)
	return nil
}
