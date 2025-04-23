package utils

import (
	"encoding/json"
	"fmt"
	"github.com/tniah/authlib/types"
	"mime"
	"net/http"
	"net/url"
)

func ContentType(r *http.Request) (types.ContentType, error) {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return "", err
	}

	return types.NewContentType(ct), nil
}

func JSONHeaders() map[string]string {
	return map[string]string{
		"Content-Type":  "application/json;charset=UTF-8",
		"Cache-Control": "no-store",
		"Pragma":        "no-cache",
	}
}

func JSONResponse(rw http.ResponseWriter, payload map[string]interface{}, status ...int) error {
	for k, v := range JSONHeaders() {
		rw.Header().Set(k, v)
	}

	st := http.StatusOK
	if len(status) > 0 {
		st = status[0]
	}
	rw.WriteHeader(st)

	return json.NewEncoder(rw).Encode(payload)
}

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

	rw.Header().Set("Location", location)
	rw.WriteHeader(http.StatusFound)
	return nil
}
