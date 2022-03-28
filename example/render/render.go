package render

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin/render"
	"github.com/google/uuid"
	errcode "github.com/liaoyijun/ginapi/example/errors"
)

type Render struct{}

func NewRender() *Render {
	return &Render{}
}

func (r *Render) Error(err error) render.Render {
	code := errcode.Code(err)
	return Response{
		Result:    "error",
		ErrorCode: code,
		Msg:       err.Error(),
		TimeStamp: int64(time.Now().UnixNano() / 1e6),
		RequestId: uuid.New().String(),
	}
}

func (r *Render) Success(obj interface{}) render.Render {
	return Response{
		Result:    "ok",
		Msg:       "success",
		Data:      obj,
		TimeStamp: int64(time.Now().UnixNano() / 1e6),
		RequestId: uuid.New().String(),
	}
}

func (r *Render) Unmarshal(body []byte, code int, obj interface{}) error {
	if code == 200 {
		out := Response{Data: obj}

		if err := json.Unmarshal(body, &out); err != nil {
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
		return errors.New(http.StatusText(code))
	}
}

type Response struct {
	Result    string            `json:"result"`
	ErrorCode errcode.ErrorCode `json:"error_code,omitempty"`
	Msg       string            `json:"msg"`
	Data      interface{}       `json:"data"`
	TimeStamp int64             `json:"time-stamp"`
	RequestId string            `json:"request-id"`
}

var jsonContentType = []string{"application/json; charset=utf-8"}

// Render (JSON) writes data with custom ContentType.
func (r Response) Render(w http.ResponseWriter) (err error) {
	if err = WriteJSON(w, r); err != nil {
		panic(err)
	}
	return
}

// WriteContentType (JSON) writes JSON ContentType.
func (r Response) WriteContentType(w http.ResponseWriter) {
	writeContentType(w, jsonContentType)
}

// WriteJSON marshals the given interface object and writes it with custom ContentType.
func WriteJSON(w http.ResponseWriter, obj interface{}) error {
	writeContentType(w, jsonContentType)
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = w.Write(jsonBytes)
	return err
}

func writeContentType(w http.ResponseWriter, value []string) {
	header := w.Header()
	if val := header["Content-Type"]; len(val) == 0 {
		header["Content-Type"] = value
	}
}
