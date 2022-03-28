package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrCode_Error(t *testing.T) {
	err := ErrRecordNotFound
	fmt.Println(err, ErrorCode(err).Int64())
	err1 := errors.New("dddddd")
	code := Code(nil).Int64()
	fmt.Println(code, err1)
}
