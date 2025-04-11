package rfc6750

import "time"

type GeneratorOptions struct {
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	randStringGenerator RandStringGenerator
}

func NewGeneratorOptions() *GeneratorOptions {
	return &GeneratorOptions{}
}
