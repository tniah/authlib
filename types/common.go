package types

type SpaceDelimitedArray []string

type StringPointer *string

func NewStringPtr(s string) StringPointer {
	return &s
}
