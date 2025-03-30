package common

func DefaultJSONHeader() map[string]string {
	return map[string]string{
		HeaderContentType:  ContentTypeJSON,
		HeaderCacheControl: CacheControlNoStore,
		HeaderPragma:       PragmaNoCache,
	}
}
