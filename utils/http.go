package utils

import (
	"encoding/json"
	"github.com/tniah/authlib/types"
	"mime"
	"net/http"
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
