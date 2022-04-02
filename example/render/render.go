package render

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin/render"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	errcode "github.com/liaoyijun/ginapi/example/errors"
)

type Render struct{}

func NewRender() *Render {
	return &Render{}
}

func (r *Render) Marshal(obj interface{}) render.Render {
	if err, ok := obj.(error); ok {
		return render.JSON{Data: JSON{
			Result:    "error",
			ErrorCode: errcode.Code(err),
			Msg:       err.Error(),
			TimeStamp: int64(time.Now().UnixNano() / 1e6),
			RequestId: uuid.New().String(),
		}}
	}
	return render.JSON{Data: JSON{
		Result:    "ok",
		Msg:       "success",
		Data:      obj,
		TimeStamp: int64(time.Now().UnixNano() / 1e6),
		RequestId: uuid.New().String(),
	}}
}

func (r *Render) Unmarshal(resp *resty.Response, obj interface{}) error {
	if resp.StatusCode() == 200 {
		out := JSON{Data: obj}

		if err := json.Unmarshal(resp.Body(), &out); err != nil {
			return err
		}
		if out.Result != "ok" {
			if out.ErrorCode > 0 {
				return out.ErrorCode
			}

			return errors.New(out.Msg)
		}
		return nil
	} else {
		return errors.New(http.StatusText(resp.StatusCode()))
	}
}

type JSON struct {
	Result    string            `json:"result"`
	ErrorCode errcode.ErrorCode `json:"error_code,omitempty"`
	Msg       string            `json:"msg"`
	Data      interface{}       `json:"data"`
	TimeStamp int64             `json:"time-stamp"`
	RequestId string            `json:"request-id"`
}
