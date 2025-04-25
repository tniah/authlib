package types

type CodeChallengeMethod string

func NewCodeChallengeMethod(s string) CodeChallengeMethod {
	return CodeChallengeMethod(s)
}

func (m CodeChallengeMethod) IsPlain() bool {
	return m == CodeChallengeMethodPlain
}

func (m CodeChallengeMethod) IsS256() bool {
	return m == CodeChallengeMethodS256
}

func (m CodeChallengeMethod) IsEmpty() bool {
	return m == ""
}

func (m CodeChallengeMethod) String() string {
	return string(m)
}
