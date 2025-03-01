package models

type User interface {
	GetSubjectID() string
	GetValue(k string) string
}
