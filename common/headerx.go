package common

const (
	HeaderContentType   = "Content-Type"
	HeaderCacheControl  = "Cache-Control"
	HeaderPragma        = "Pragma"
	ContentTypeJSON     = "application/json;charset=UTF-8"
	CacheControlNoStore = "no-store"
	PragmaNoCache       = "no-cache"
)

func DefaultJSONHeader() map[string]string {
	return map[string]string{
		HeaderContentType:  ContentTypeJSON,
		HeaderCacheControl: CacheControlNoStore,
		HeaderPragma:       PragmaNoCache,
	}
}
