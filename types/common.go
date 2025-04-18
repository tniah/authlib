package types

type SpaceDelimitedArray []string

func NewSpaceDelimitedArray(arr ...string) SpaceDelimitedArray {
	return arr
}
