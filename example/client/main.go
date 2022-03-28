package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"os"

	render "github.com/liaoyijun/ginapi/example/render"
	ginapi "github.com/liaoyijun/ginapi/example/routes/user/v1"
)

func main() {
	client := ginapi.NewUserClient(render.NewRender())
	resp, err := client.Save(context.Background(), &ginapi.SaveRequest{
		Id:   111,
		Name: "test",
	})
	fmt.Println(resp, err)
	// avatar, err := ReadFileHeader("./test.png")
	// if err != nil {
	// 	panic(err)
	// }
	// client := ginapi.NewUserClient(render.NewRender())
	// resp, err := client.Upload(context.Background(), &ginapi.UploadRequest{
	// 	Name:   "test",
	// 	Avatar: avatar,
	// })
	// fmt.Println(resp, err)
}

func ReadFileHeader(filename string) (*multipart.FileHeader, error) {
	buf := &bytes.Buffer{}
	writer := multipart.NewWriter(buf)

	// this step is very important
	dst, err := writer.CreateFormFile("fieldname", filename)
	if err != nil {
		return nil, err
	}

	// open file handle
	src, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	// iocopy
	_, err = io.Copy(dst, src)
	if err != nil {
		return nil, err
	}
	writer.Close()

	reader := multipart.NewReader(buf, writer.Boundary())
	form, err := reader.ReadForm(32 << 20)
	if err != nil {
		return nil, err
	}

	fhs := form.File["fieldname"]
	return fhs[0], nil
}
