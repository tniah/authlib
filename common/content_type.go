package common

import (
	"mime"
	"net/http"
)

func IsContentType(r *http.Request, contentType string) bool {
	ct, _, err := mime.ParseMediaType(r.Header.Get(HeaderContentType))
	if err != nil {
		return false
	}

	return ct == contentType
}

func IsXWwwFormUrlencodedContentType(r *http.Request) bool {
	return IsContentType(r, ContentTypeXWwwFormUrlencoded)
}
