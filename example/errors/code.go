package errors

type ErrorCode int64

const (
	ErrRecordNotFound ErrorCode = 1
)

var codeText = map[ErrorCode]string{
	ErrRecordNotFound: "成功",
}

//	根据错误码返回对应的错误描述
func CodeText(code ErrorCode) string {
	return codeText[code]
}
