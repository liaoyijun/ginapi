package errors

func (code ErrorCode) Error() string {
	return CodeText(code)
}

func (code ErrorCode) Int64() int64 {
	return int64(code)
}

func Code(err error) ErrorCode {
	if val, ok := err.(ErrorCode); ok {
		return val
	}
	return 0
}
