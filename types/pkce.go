package types

type CodeChallengeMethod string

func NewCodeChallengeMethod(s string) CodeChallengeMethod {
	return CodeChallengeMethod(s)
}

func (m CodeChallengeMethod) Equal(o CodeChallengeMethod) bool {
	return m == o
}

func (m CodeChallengeMethod) IsPlain() bool {
	return m.Equal(CodeChallengeMethodPlain)
}

func (m CodeChallengeMethod) IsS256() bool {
	return m.Equal(CodeChallengeMethodS256)
}

func (m CodeChallengeMethod) IsEmpty() bool {
	return m.Equal("")
}

func (m CodeChallengeMethod) String() string {
	return string(m)
}
