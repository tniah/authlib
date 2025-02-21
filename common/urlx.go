package common

import (
	"fmt"
	"net/url"
)

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
