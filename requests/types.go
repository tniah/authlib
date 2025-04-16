package requests

import "golang.org/x/text/language"

type ResponseType string

type ResponseMode string

type Display string

type Locales []language.Tag

type CodeChallengeMethod string

type SpaceDelimitedArray []string

func NewMaxAge(i uint) *uint {
	return &i
}

func NewLocales(locales []string) Locales {
	out := make(Locales, 0, len(locales))
	for _, locale := range locales {
		tag, err := language.Parse(locale)
		if err == nil && !tag.IsRoot() {
			out = append(out, tag)
		}
	}
	return out
}
