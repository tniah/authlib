package utils

import "reflect"

func IsNil(v interface{}) bool {
	val := reflect.ValueOf(v)
	if !val.IsValid() || val.Kind() == reflect.Ptr && val.IsNil() {
		return true
	}

	return false
}
