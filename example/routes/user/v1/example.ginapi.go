package v1

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"github.com/go-resty/resty/v2"
	"mime/multipart"
	"net/http"
)

type Render interface {
	Marshal(interface{}) render.Render
	Unmarshal(*resty.Response, interface{}) error
}

type UserService interface {
	Upload(ctx *gin.Context, req *UploadRequest) (*UploadResponse, error)
	Save(ctx *gin.Context, req *SaveRequest) (*SaveResponse, error)
}

type RequestOption func(*resty.Request)

type UserClient interface {
	Upload(ctx context.Context, req *UploadRequest, opts ...RequestOption) (*UploadResponse, error)
	Save(ctx context.Context, req *SaveRequest, opts ...RequestOption) (*SaveResponse, error)
}

func RegisterService(engine *gin.Engine, render Render, service UserService, middleware ...gin.HandlerFunc) {
	engine.POST("upload", append([]gin.HandlerFunc{func(ctx *gin.Context) {
		var req UploadRequest
		if err := ctx.ShouldBind(&req); err != nil {
			ctx.Render(200, render.Marshal(err))
			return
		}
		resp, err := service.Upload(ctx, &req)
		if err != nil {
			ctx.Render(200, render.Marshal(err))
			return
		}
		ctx.Render(200, render.Marshal(resp))
	}}, middleware...)...)
	engine.PUT("save/:id", append([]gin.HandlerFunc{func(ctx *gin.Context) {
		var req SaveRequest
		if err := ctx.ShouldBindUri(&req); err != nil {
			ctx.Render(200, render.Marshal(err))
			return
		}
		if err := ctx.ShouldBind(&req); err != nil {
			ctx.Render(200, render.Marshal(err))
			return
		}
		resp, err := service.Save(ctx, &req)
		if err != nil {
			ctx.Render(200, render.Marshal(err))
			return
		}
		ctx.Render(200, render.Marshal(resp))
	}}, middleware...)...)
}

type UploadRequest struct {
	Avatar *multipart.FileHeader `form:"avatar" json:"avatar"`
	Name   string                `form:"name" json:"name"`
}

type UploadResponse struct {
	Results []string `json:"results"`
}

type SaveRequest struct {
	Id     int64             `json:"id" uri:"id"`
	Name   string            `form:"name" json:"name"`
	Person map[int64]*Person `form:"person" json:"person"`
}

type Person struct {
	Age   int64 `form:"age" json:"age"`
	Level int64 `form:"level" json:"level"`
}

type SaveResponse struct {
	Results []string `json:"results"`
}

type userClient struct {
	scheme string
	host   string
	client *resty.Client
	render Render
}

type clientOption func(*userClient)

func WithScheme(scheme string) clientOption {
	return func(c *userClient) {
		c.scheme = scheme
	}
}

func WithHost(host string) clientOption {
	return func(c *userClient) {
		c.host = host
	}
}

func WithClient(client *http.Client) clientOption {
	return func(c *userClient) {
		c.client = resty.NewWithClient(client)
	}
}

func NewUserClient(render Render, opts ...clientOption) UserClient {
	c := userClient{
		client: resty.NewWithClient(http.DefaultClient),
		host:   "localhost:8080",
		render: render,
		scheme: "http",
	}
	for _, o := range opts {
		o(&c)
	}
	return &c
}

func (c *userClient) Upload(ctx context.Context, req *UploadRequest, opts ...RequestOption) (*UploadResponse, error) {
	url := fmt.Sprintf("%s://%s/upload", c.scheme, c.host)
	var result UploadResponse
	r := c.client.R()
	for _, o := range opts {
		o(r)
	}
	_avatar, err := req.Avatar.Open()
	if err != nil {
		return nil, err
	}
	r.SetFileReader("avatar", req.Avatar.Filename, _avatar)
	resp, err := r.Post(url)
	if err != nil {
		return nil, err
	}
	if err := c.render.Unmarshal(resp, &result); err != nil {
		return nil, err
	} else {
		return &result, nil
	}
}

func (c *userClient) Save(ctx context.Context, req *SaveRequest, opts ...RequestOption) (*SaveResponse, error) {
	url := fmt.Sprintf("%s://%s/save/{id}", c.scheme, c.host)
	var result SaveResponse
	r := c.client.R()
	for _, o := range opts {
		o(r)
	}
	r.SetPathParams(map[string]string{"id": fmt.Sprintf("%d", req.Id)})
	r.SetBody(req)
	resp, err := r.Put(url)
	if err != nil {
		return nil, err
	}
	if err := c.render.Unmarshal(resp, &result); err != nil {
		return nil, err
	} else {
		return &result, nil
	}
}
