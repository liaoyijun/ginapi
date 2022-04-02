package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	render "github.com/liaoyijun/ginapi/example/render"
	ginapi "github.com/liaoyijun/ginapi/example/routes/user/v1"
)

func main() {
	r := gin.Default()
	ginapi.RegisterService(r, render.NewRender(), &UserController{}, func(ctx *gin.Context) {
		ctx.Next()
		fmt.Println("middleware")
	})
	r.Run()
}

type UserController struct{}

func (c *UserController) Upload(ctx *gin.Context, req *ginapi.UploadRequest) (*ginapi.UploadResponse, error) {
	file, err := req.Avatar.Open()
	fmt.Println(req.Avatar, req.Avatar.Filename, file, err)
	ctx.SaveUploadedFile(req.Avatar, "./test.png")
	return &ginapi.UploadResponse{
		Results: []string{"test"},
	}, nil
}

func (c *UserController) Save(ctx *gin.Context, req *ginapi.SaveRequest) (*ginapi.SaveResponse, error) {
	fmt.Println(req.Id, req.Name)
	// return nil, errors.New("this is a error")
	return &ginapi.SaveResponse{
		Results: []string{"test"},
	}, nil
}
