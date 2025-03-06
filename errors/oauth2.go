package errors

import (
	"fmt"
	"net/http"
)

type OAuth2Error struct {
	// Code a short-string error code
	Code error
	// Description human-readable text providing additional information,
	// used to assist the client developer in understanding the error that occurred
	Description string
	// URI a URI identifying a human-readable web page with information about the error
	URI string
	// State
	// HttpCode Http status code
	HttpCode int
	// HttpHeader Http header
	HttpHeader http.Header
}

func NewOAuth2Error(code error, args ...string) *OAuth2Error {
	httpCode := http.StatusBadRequest
	if v, ok := HttpCodes[code]; ok {
		httpCode = v
	}

	e := &OAuth2Error{
		Code:       code,
		HttpCode:   httpCode,
		HttpHeader: make(http.Header),
	}

	if len(args) > 0 {
		e.Description = args[0]
	}

	if len(args) > 1 {
		e.URI = args[1]
	}

	if e.Description == "" {
		if v, ok := Descriptions[code]; ok {
			e.Description = v
		}
	}

	return e
}

func (e *OAuth2Error) Error() string {
	return fmt.Sprintf("error=%v | description=%s", e.Code, e.Description)
}

func (e *OAuth2Error) SetHeader(key, value string) {
	if e.HttpHeader == nil {
		e.HttpHeader = make(http.Header)
	}
	e.HttpHeader.Set(key, value)
}

func (e *OAuth2Error) Data() map[string]interface{} {
	data := map[string]interface{}{
		ErrCode: fmt.Sprintf("%v", e.Code),
	}

	if v := e.Description; v != "" {
		data[ErrDescription] = v
	}

	if v := e.URI; v != "" {
		data[ErrUri] = v
	}

	return data
}

func (e *OAuth2Error) Response() (statusCode int, header http.Header, data map[string]interface{}) {
	return e.HttpCode, e.HttpHeader, e.Data()
}
