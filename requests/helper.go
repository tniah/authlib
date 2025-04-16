package requests

func isRequired(defaultValue bool, opts ...bool) bool {
	if len(opts) > 0 {
		return opts[0]
	}

	return defaultValue
}
