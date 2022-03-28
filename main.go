// ginapi  --out=../ginapi/common/v1/ example.ginapi
package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/alecthomas/repr"
	ff "github.com/dave/jennifer/jen"
)

type Ginapi struct {
	Pos     lexer.Position
	Entries []*Entry `( @@ ";"* )*`
}

func (g *Ginapi) Package() string {
	for _, v := range g.Entries {
		if v.Package != "" {
			return v.Package
		}
	}
	return ""
}

func (g *Ginapi) Host() string {
	for _, v := range g.Entries {
		if v.Host != "" {
			return v.Host
		}
	}
	return "http://localhost:80"
}

func (g *Ginapi) Group() string {
	for _, v := range g.Entries {
		if strings.Trim(v.Group, "\"") != "" {
			return v.Group
		}
	}
	return "\"/\""
}

func (g *Ginapi) Router() *Router {
	for _, v := range g.Entries {
		if v.Router != nil {
			return v.Router
		}
	}
	return nil
}

func (g *Ginapi) Messages() []*Message {
	var out []*Message
	for _, v := range g.Entries {
		if v.Message != nil {
			out = append(out, v.Message)
		}
	}
	return out
}

type Entry struct {
	Pos lexer.Position

	Package string   ` "package" @(Ident ( "." Ident )*)`
	Host    string   `| "host" "=" @String`
	Group   string   `| "group" "=" @String`
	Router  *Router  `| @@`
	Message *Message `| @@`
}

type Value struct {
	Pos lexer.Position

	String    *string  `  @String`
	Number    *float64 `| @Float`
	Int       *int64   `| @Int`
	Bool      *bool    `| (@"true" | "false")`
	Reference *string  `| @Ident @( "." Ident )*`
	Map       *Map     `| @@`
	Array     *Array   `| @@`
}

type Array struct {
	Pos lexer.Position

	Elements []*Value `"[" ( @@ ( ","? @@ )* )? "]"`
}

type Map struct {
	Pos lexer.Position

	Entries []*MapEntry `"{" ( @@ ( ( "," )? @@ )* )? "}"`
}

type MapEntry struct {
	Pos lexer.Position

	Key   *Value `@@`
	Value *Value `":"? @@`
}

type Router struct {
	Pos lexer.Position

	Name    string         `"router" @Ident`
	Entries []*RouterEntry `"{" ( @@ ";"? )* "}"`
}

type RouterEntry struct {
	Pos lexer.Position

	Route *Route ` @@`
}

func (r *RouterEntry) CallBlock() []ff.Code {
	// todo `HEAD` `POST` `OPTIONS` `PUT` `DELETE` `TRACE` `CONNECT`
	blocks := r.Route.ShouldBindBlock()
	blocks = append(blocks,
		ff.Id("resp").Op(",").Id("err").Op(":=").Id(fmt.Sprintf("%s.%s", "service", r.Route.Name)).Call(
			ff.Id("ctx"),
			ff.Op("&").Id("req"),
		),
		ff.If(
			ff.Err().Op("!=").Nil(),
		).Block(
			ff.Id("ctx.Render").Call(
				ff.Id("200"),
				ff.Id("render.Error").Call(
					ff.Id("err"),
				),
			),
			ff.Return(),
		),
		ff.Id("ctx.Render").Call(
			ff.Id("200"),
			ff.Id("render.Success").Call(
				ff.Id("resp"),
			),
		),
	)
	return []ff.Code{
		ff.Id(r.Route.Path),
		ff.Func().Params(
			ff.Id("ctx").Id("*gin.Context"),
		).Block(blocks...),
	}
}

type Route struct {
	Pos lexer.Position

	Method   string `@Ident`
	Name     string ` @Ident`
	Path     string `"(" @String ","`
	Request  *Type  ` @@ ")"`
	Response *Type  `"returns" "(" @@ ")"`
}

func (route *Route) ShouldBindBlock() []ff.Code {
	codes := []ff.Code{
		ff.Var().Id("req").Id(route.Request.Reference),
	}
	params := route.ParseUri()
	if len(params) > 0 {
		codes = append(codes, ff.If(
			ff.Err().Op(":=").Id("ctx.ShouldBindUri").Call(
				ff.Op("&").Id("req"),
			),
			ff.Err().Op("!=").Nil(),
		).Block(
			ff.Id("ctx.Render").Call(
				ff.Id("200"),
				ff.Id("render.Error").Call(
					ff.Id("err"),
				),
			),
			ff.Return(),
		))
	}
	codes = append(codes, ff.If(
		ff.Err().Op(":=").Id("ctx.ShouldBind").Call(
			ff.Op("&").Id("req"),
		),
		ff.Err().Op("!=").Nil(),
	).Block(
		ff.Id("ctx.Render").Call(
			ff.Id("200"),
			ff.Id("render.Error").Call(
				ff.Id("err"),
			),
		),
		ff.Return(),
	))
	return codes
}

func (route *Route) ParseUri() map[string]struct{} {
	params := make(map[string]struct{})
	path := strings.Trim(route.Path, "\"")
	for path != "" {
		// Find prefix until first wildcard
		wildcard, i, valid := FindWildcard(path)
		if i < 0 { // No wildcard found
			break
		}

		// The wildcard name must not contain ':' and '*'
		if !valid {
			panic("only one wildcard per path segment is allowed, has: '" +
				wildcard + "' in path '" + path + "'")
		}

		// check if the wildcard has a name
		if len(wildcard) < 2 {
			panic("wildcards must be named with a non-empty name in path '" + path + "'")
		}

		path = path[i:]

		if len(wildcard) > len(path) {
			break
		}
		path = path[len(wildcard):]
		params[wildcard] = struct{}{}
	}
	return params
}

type Message struct {
	Pos lexer.Position

	Name    string          `"message" @Ident`
	Entries []*MessageEntry `"{" @@* "}"`
}

func (message *Message) Uri() ff.Dict {
	params := make(ff.Dict)
	for _, v := range message.Entries {
		if v.Field.HasTag("uri") {
			switch v.Field.Type.Scalar {
			case Int32, Int64, Uint32, Uint64, Sint32, Sint64, Fixed32, Fixed64, SFixed32, SFixed64:
				params[ff.Lit(v.Field.Name)] = ff.Id("fmt.Sprintf").Call(
					ff.Lit("%d"),
					ff.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case Float, Double:
				params[ff.Lit(v.Field.Name)] = ff.Id("fmt.Sprintf").Call(
					ff.Lit("%f"),
					ff.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case Bool:
				params[ff.Lit(v.Field.Name)] = ff.Id("fmt.Sprintf").Call(
					ff.Lit("%t"),
					ff.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case String:
				params[ff.Lit(v.Field.Name)] = ff.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name)))
			}
		}
	}
	return params
}

func (message *Message) Form() ff.Dict {
	params := make(ff.Dict)
	for _, v := range message.Entries {
		if v.Field.HasTag("form") && v.Field.Type.Scalar == File {
			switch v.Field.Type.Scalar {
			case Int32, Int64, Uint32, Uint64, Sint32, Sint64, Fixed32, Fixed64, SFixed32, SFixed64:
				params[ff.Lit(v.Field.Name)] = ff.Id("fmt.Sprintf").Call(
					ff.Lit("%d"),
					ff.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case Float, Double:
				params[ff.Lit(v.Field.Name)] = ff.Id("fmt.Sprintf").Call(
					ff.Lit("%f"),
					ff.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case Bool:
				params[ff.Lit(v.Field.Name)] = ff.Id("fmt.Sprintf").Call(
					ff.Lit("%t"),
					ff.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case String:
				params[ff.Lit(v.Field.Name)] = ff.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name)))
			}
		}
	}
	return params
}

func (message *Message) File() []ff.Code {
	var codes []ff.Code
	for _, v := range message.Entries {
		if v.Field.Type.Scalar == File {
			_temp := "_" + v.Field.Name
			codes = append(
				codes,
				ff.Id(_temp).Op(",").Err().Op(":=").Id("req").Op(".").Id(ToCamelCase(v.Field.Name)).Op(".").Id("Open").Call(),
				ff.If(
					ff.Err().Op("!=").Nil(),
				).Block(
					ff.Return(
						ff.Id("nil"),
						ff.Id("err"),
					),
				),
				ff.Id("r.SetFileReader").Call(
					ff.Id("\""+v.Field.Name+"\""),
					ff.Id("req").Op(".").Id(ToCamelCase(v.Field.Name)).Op(".").Id("Filename"),
					ff.Id(_temp),
				),
			)
		}
	}
	return codes
}

type MessageEntry struct {
	Pos lexer.Position

	Message *Message ` ( @@`
	Field   *Field   ` | @@ ) ";"*`
}

type Field struct {
	Pos lexer.Position

	Optional bool `(   @"optional"`
	Required bool `  | @"required"`
	Repeated bool `  | @"repeated" )?`

	Type *Type  `@@`
	Name string `@Ident`
	Tag  string `"=" @String`
}

func (field *Field) Statement() ff.Code {
	return field.Type.Scalar.ScalarStatement(field)
}

func (field *Field) HasTag(tag string) bool {
	return strings.Contains(field.Tag, tag+":")
}

func (field *Field) Tags() map[string]string {
	out := make(map[string]string)
	tag := strings.Trim(field.Tag, "\"")
	if tag == "" {
		return out
	}
	items := strings.Split(tag, ";")
	for _, item := range items {
		val := strings.Split(item, ":")
		if len(val) == 2 {
			out[val[0]] = val[1]
		} else if len(val) == 1 {
			out["json"] = val[0]
		}
	}
	if _, ok := out["json"]; !ok {
		out["json"] = field.Name
	}
	return out
}

type Scalar int

const (
	None Scalar = iota
	Double
	Float
	Int32
	Int64
	Uint32
	Uint64
	Sint32
	Sint64
	Fixed32
	Fixed64
	SFixed32
	SFixed64
	Bool
	String
	Bytes
	File
)

var scalarString = map[Scalar]string{
	None: "None", Double: "Double", Float: "Float", Int32: "Int32", Int64: "Int64", Uint32: "Uint32",
	Uint64: "Uint64", Sint32: "Sint32", Sint64: "Sint64", Fixed32: "Fixed32", Fixed64: "Fixed64",
	SFixed32: "SFixed32", SFixed64: "SFixed64", Bool: "Bool", String: "String", Bytes: "Bytes", File: "File",
}

type ScalarStatementOption func(*Field) ff.Code

func StringStatement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		if field.Repeated {
			return ff.Id(ToCamelCase(field.Name)).Op("[]").String().Tag(field.Tags())
		} else {
			return ff.Id(ToCamelCase(field.Name)).String().Tag(field.Tags())
		}
	}
}

func Int32Statement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		if field.Repeated {
			return ff.Id(ToCamelCase(field.Name)).Op("[]").Int32().Tag(field.Tags())
		} else {
			return ff.Id(ToCamelCase(field.Name)).Int32().Tag(field.Tags())
		}
	}
}

func Int64Statement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		if field.Repeated {
			return ff.Id(ToCamelCase(field.Name)).Op("[]").Int64().Tag(field.Tags())
		} else {
			return ff.Id(ToCamelCase(field.Name)).Int64().Tag(field.Tags())
		}
	}
}

func Uint32Statement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		if field.Repeated {
			return ff.Id(ToCamelCase(field.Name)).Op("[]").Uint32().Tag(field.Tags())
		} else {
			return ff.Id(ToCamelCase(field.Name)).Uint32().Tag(field.Tags())
		}
	}
}

func Uint64Statement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		if field.Repeated {
			return ff.Id(ToCamelCase(field.Name)).Op("[]").Uint64().Tag(field.Tags())
		} else {
			return ff.Id(ToCamelCase(field.Name)).Uint64().Tag(field.Tags())
		}
	}
}

func FloatStatement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		if field.Repeated {
			return ff.Id(ToCamelCase(field.Name)).Op("[]").Float32().Tag(field.Tags())
		} else {
			return ff.Id(ToCamelCase(field.Name)).Float32().Tag(field.Tags())
		}
	}
}

func DoubleStatement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		if field.Repeated {
			return ff.Id(ToCamelCase(field.Name)).Op("[]").Float64().Tag(field.Tags())
		} else {
			return ff.Id(ToCamelCase(field.Name)).Float64().Tag(field.Tags())
		}
	}
}

func BoolStatement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		if field.Repeated {
			return ff.Id(ToCamelCase(field.Name)).Op("[]").Bool().Tag(field.Tags())
		} else {
			return ff.Id(ToCamelCase(field.Name)).Bool().Tag(field.Tags())
		}
	}
}

func BytesStatement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		return ff.Id(ToCamelCase(field.Name)).Op("[]").Byte().Tag(field.Tags())
	}
}

func FileStatement() ScalarStatementOption {
	return func(field *Field) ff.Code {
		return ff.Id(ToCamelCase(field.Name)).Op("*").Qual("mime/multipart", "FileHeader").Tag(field.Tags())
	}
}

var scalarStatement = map[Scalar]ScalarStatementOption{
	String:   StringStatement(),
	Int32:    Int32Statement(),
	Int64:    Int64Statement(),
	Uint32:   Uint32Statement(),
	Uint64:   Uint64Statement(),
	Sint32:   Int32Statement(),
	Sint64:   Int64Statement(),
	Fixed32:  Uint32Statement(),
	Fixed64:  Uint64Statement(),
	SFixed32: Int32Statement(),
	SFixed64: Int64Statement(),
	Double:   DoubleStatement(),
	Float:    FloatStatement(),
	Bool:     BoolStatement(),
	Bytes:    BytesStatement(),
	File:     FileStatement(),
}

func (s Scalar) ScalarStatement(field *Field) ff.Code {
	return scalarStatement[s](field)
}

func (s Scalar) ScalarString() string { return scalarString[s] }

var stringToScalar = map[string]Scalar{
	"double": Double, "float": Float, "int32": Int32, "int64": Int64, "uint32": Uint32, "uint64": Uint64,
	"sint32": Sint32, "sint64": Sint64, "fixed32": Fixed32, "fixed64": Fixed64, "sfixed32": SFixed32,
	"sfixed64": SFixed64, "bool": Bool, "string": String, "bytes": Bytes, "file": File,
}

func (s *Scalar) Parse(lex *lexer.PeekingLexer) error {
	token, err := lex.Peek(0)
	if err != nil {
		return err
	}
	v, ok := stringToScalar[token.Value]
	if !ok {
		return participle.NextMatch
	}
	_, err = lex.Next()
	if err != nil {
		return err
	}
	*s = v
	return nil
}

type Type struct {
	Pos lexer.Position

	Scalar    Scalar   `  @@`
	Map       *MapType `| @@`
	Reference string   `| @(Ident ( "." Ident )*)`
}

type MapType struct {
	Pos lexer.Position

	Key   *Type `"map" "<" @@`
	Value *Type `"," @@ ">"`
}

var (
	parser = participle.MustBuild(&Ginapi{}, participle.UseLookahead(2))

	cli struct {
		Out  string `help:"out."`
		Path string `arg`
	}
)

type Generator struct {
	File  *ff.File
	Value *Ginapi
}

func NewGenerator(file *ff.File, value *Ginapi) *Generator {
	return &Generator{
		File:  file,
		Value: value,
	}
}

func (g *Generator) ServiceInterface() {
	keyword := fmt.Sprintf("%s%s", g.Value.Router().Name, "Service")
	statement := g.File.Type().Id(keyword)
	var methods []ff.Code
	for _, r := range g.Value.Router().Entries {
		methods = append(methods, ff.Id(r.Route.Name).Params(
			ff.Id("ctx").Op("*").Qual("github.com/gin-gonic/gin", "Context"),
			ff.Id("req").Op("*").Id(r.Route.Request.Reference),
		).Params(
			ff.Op("*").Id(r.Route.Response.Reference),
			ff.Id("error"),
		))
	}
	statement.Interface(methods...)
}

func (g *Generator) ClientInterface() {
	g.File.Type().Id("RequestOption").Func().Params(
		ff.Op("*").Qual("github.com/go-resty/resty/v2", "Request"),
	)

	keyword := fmt.Sprintf("%s%s", g.Value.Router().Name, "Client")
	statement := g.File.Type().Id(keyword)
	var methods []ff.Code
	for _, r := range g.Value.Router().Entries {
		methods = append(methods, ff.Id(r.Route.Name).Params(
			ff.Id("ctx").Qual("context", "Context"),
			ff.Id("req").Op("*").Id(r.Route.Request.Reference),
			ff.Id("opts").Op("...").Id("RequestOption"),
		).Params(
			ff.Op("*").Id(r.Route.Response.Reference),
			ff.Id("error"),
		))
	}
	statement.Interface(methods...)
}

func (g *Generator) RenderInterface() {
	g.File.Type().Id("Render").Interface(
		ff.Id("Error").Params(ff.Id("error")).Params(ff.Qual("github.com/gin-gonic/gin/render", "Render")),
		ff.Id("Success").Params(ff.Id("interface{}")).Params(ff.Qual("github.com/gin-gonic/gin/render", "Render")),
		ff.Id("Unmarshal").Params(
			ff.Id("[]byte"),
			ff.Id("int"),
			ff.Id("interface{}"),
		).Params(ff.Id("error")),
	)
}

func (g *Generator) RegisterService() {
	keyword := fmt.Sprintf("%s%s", g.Value.Router().Name, "Service")
	register := g.File.Func().Id("RegisterService").Params(
		ff.Id("router").Op("*").Qual("github.com/gin-gonic/gin", "Engine"),
		ff.Id("service").Id(keyword),
		ff.Id("render").Id("Render"),
	)

	var block []ff.Code
	if g.Value.Group() != "\"/\"" {
		block = append(block, ff.Id("group").Op(":=").Id("router").Dot("Group").Call(
			ff.Id(g.Value.Group()),
		))
		var routers []ff.Code
		for _, r := range g.Value.Router().Entries {
			routers = append(routers, ff.Id("group").Dot(strings.ToUpper(r.Route.Method)).Call(r.CallBlock()...))
		}
		block = append(block, ff.Block(routers...))
	} else {
		for _, r := range g.Value.Router().Entries {
			block = append(block, ff.Id("router").Dot(strings.ToUpper(r.Route.Method)).Call(r.CallBlock()...))
		}
	}

	register.Block(block...)
}

func (g *Generator) MessageStruct() {
	for _, m := range g.Value.Messages() {
		var fields []ff.Code
		for _, f := range m.Entries {
			fields = append(fields, f.Field.Statement())
		}
		g.File.Type().Id(m.Name).Struct(fields...)
	}
}

func (g *Generator) ClientImplement() {
	client := fmt.Sprintf("%s%s", strings.ToLower(g.Value.Router().Name), "Client")
	g.File.Type().Id(client).Struct(
		ff.Id("scheme").String(),
		ff.Id("host").String(),
		ff.Id("client").Op("*").Qual("github.com/go-resty/resty/v2", "Client"),
		ff.Id("render").Id("Render"),
	)
	g.File.Type().Id("clientOption").Func().Params(
		ff.Op("*").Id(client),
	)
	g.File.Func().Id("WithScheme").Params(
		ff.Id("scheme").String(),
	).Params(
		ff.Id("clientOption"),
	).Block(
		ff.Return(
			ff.Func().Params(
				ff.Id("c").Op("*").Id(client),
			).Block(
				ff.Id("c").Op(".").Id("scheme").Op("=").Id("scheme"),
			),
		),
	)
	g.File.Func().Id("WithHost").Params(
		ff.Id("host").String(),
	).Params(
		ff.Id("clientOption"),
	).Block(
		ff.Return(
			ff.Func().Params(
				ff.Id("c").Op("*").Id(client),
			).Block(
				ff.Id("c").Op(".").Id("host").Op("=").Id("host"),
			),
		),
	)
	g.File.Func().Id("WithClient").Params(
		ff.Id("client").Op("*").Qual("net/http", "Client"),
	).Params(
		ff.Id("clientOption"),
	).Block(
		ff.Return(
			ff.Func().Params(
				ff.Id("c").Op("*").Id(client),
			).Block(
				ff.Id("c").Op(".").Id("client").Op("=").Qual("github.com/go-resty/resty/v2", "NewWithClient").Call(
					ff.Id("client"),
				),
			),
		),
	)

	implement := fmt.Sprintf("%s%s", g.Value.Router().Name, "Client")
	_url, err := url.Parse(strings.Trim(g.Value.Host(), "\""))
	if err != nil {
		panic(err)
	}
	g.File.Func().Id(fmt.Sprintf("New%s", implement)).Params(
		ff.Id("render").Id("Render"),
		ff.Id("opts").Op("...").Id("clientOption"),
	).Params(
		ff.Id(implement),
	).Block(
		ff.Id("c").Op(":=").Id(client).Values(ff.Dict{
			ff.Id("scheme"): ff.Lit(_url.Scheme),
			ff.Id("host"):   ff.Lit(_url.Host),
			ff.Id("client"): ff.Qual("github.com/go-resty/resty/v2", "NewWithClient").Call(
				ff.Qual("net/http", "DefaultClient"),
			),
			ff.Id("render"): ff.Id("render"),
		}),
		ff.For(
			ff.Id("_").Op(",").Id("o").Op(":=").Range().Id("opts").Block(
				ff.Id("o").Call(
					ff.Op("&").Id("c"),
				),
			),
		),
		ff.Return(
			ff.Op("&").Id("c"),
		),
	)
	g.MethodStatement(client)
}

func (g *Generator) MethodStatement(client string) {
	for _, r := range g.Value.Router().Entries {
		var statements []ff.Code

		path := strings.Trim(r.Route.Path, "\"")
		params := r.Route.ParseUri()
		if len(params) > 0 {
			for old := range params {
				new := fmt.Sprintf("{%s}", old[1:])
				path = strings.Replace(path, old, new, 1)
			}
		}
		statements = g.ParamsCode(strings.Trim(r.Route.Method, "\""), strings.Trim(g.Value.Group(), "\"")+path, r.Route.Request.Reference, r.Route.Response.Reference)

		g.File.Func().Params(
			ff.Id("c").Op("*").Id(client),
		).Id(r.Route.Name).Params(
			ff.Id("ctx").Qual("context", "Context"),
			ff.Id("req").Op("*").Id(r.Route.Request.Reference),
			ff.Id("opts").Op("...").Id("RequestOption"),
		).Params(
			ff.Op("*").Id(r.Route.Response.Reference),
			ff.Id("error"),
		).Block(statements...)
	}
}

func (g *Generator) ParamsCode(method string, path string, req string, resp string) []ff.Code {
	uri := make(ff.Dict)
	form := make(ff.Dict)
	file := []ff.Code{}
	for _, message := range g.Value.Messages() {
		if message.Name == req {
			uri = message.Uri()
			form = message.Form()
			file = message.File()
		}
	}
	path = "%s://%s" + path
	statements := []ff.Code{
		ff.Id("url").Op(":=").Qual("fmt", "Sprintf").Call(
			ff.Lit(path),
			ff.Id("c.scheme"),
			ff.Id("c.host"),
		),
		ff.Var().Id("result").Id(resp),
		ff.Id("r").Op(":=").Id("c.client.R()"),
		ff.For(
			ff.Id("_").Op(",").Id("o").Op(":=").Range().Id("opts").Block(
				ff.Id("o").Call(
					ff.Id("r"),
				),
			),
		),
	}
	if len(uri) > 0 {
		statements = append(
			statements,
			ff.Id("r.SetPathParams").Call(
				ff.Map(ff.String()).String().Values(uri),
			),
		)
	}
	if method == "get" {
		if len(form) > 0 {
			statements = append(
				statements,
				ff.Id("r.SetQueryParams").Call(
					ff.Map(ff.String()).String().Values(form),
				),
			)
		}
	} else {
		if len(file) > 0 {
			statements = append(
				statements,
				file...,
			)
			if len(form) > 0 {
				statements = append(
					statements,
					ff.Id("r.SetFormData").Call(
						ff.Map(ff.String()).String().Values(form),
					),
				)
			}
		} else {
			statements = append(
				statements,
				ff.Id("r.SetBody").Call(
					ff.Id("req"),
				),
			)
		}
	}

	statements = append(
		statements,
		ff.Id("resp").Op(",").Err().Op(":=").Id("r").Op(".").Id(ToCamelCase(strings.Trim(method, "\""))).Call(
			ff.Id("url"),
		),
	)
	statements = append(
		statements,
		ff.If(
			ff.Err().Op("!=").Nil(),
		).Block(
			ff.Return(
				ff.Id("nil"),
				ff.Id("err"),
			),
		),
		ff.If(
			ff.Err().Op(":=").Id("c.render.Unmarshal").Call(
				ff.Id("resp.Body()"),
				ff.Id("resp.StatusCode()"),
				ff.Op("&").Id("result"),
			),
			ff.Err().Op("!=").Nil(),
		).Block(
			ff.Return(
				ff.Id("nil"),
				ff.Id("err"),
			),
		).Else().Block(
			ff.Return(
				ff.Id("&result"),
				ff.Id("nil"),
			),
		),
	)
	return statements
}

func main() {
	kong.Parse(&cli)
	file := cli.Path
	api := &Ginapi{}
	r, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	if err = parser.Parse("", r, api); err != nil {
		panic(err)
	}

	repr.Println(api, repr.Hide(&lexer.Position{}))

	f0 := ff.NewFile(api.Package())
	f0.ImportName("context", "context")
	f0.ImportName("net/http", "http")
	f0.ImportName("github.com/gin-gonic/gin", "gin")
	f0.ImportName("github.com/gin-gonic/gin/render", "render")
	f0.ImportName("github.com/go-resty/resty/v2", "resty")

	g := NewGenerator(f0, api)

	g.RenderInterface()

	// service interface
	g.ServiceInterface()

	// client interface
	g.ClientInterface()

	// router
	g.RegisterService()

	// message
	g.MessageStruct()

	// client
	g.ClientImplement()

	dir := strings.TrimRight(cli.Out, " ")
	exists, err := CheckPathExists(dir)
	if err != nil {
		panic(err)
	}
	if !exists {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			panic(err)
		}
	}

	filename := fmt.Sprintf("%s/%s.go", cli.Out, filepath.Base(api.Pos.Filename))
	if err := f0.Save(filename); err != nil {
		fmt.Println(err)
	}
}

func CheckPathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

var reg = regexp.MustCompile("(_|-)([a-zA-Z]+)")

func ToCamelCase(str string) string {
	camel := reg.ReplaceAllString(str, " $2")
	camel = strings.Title(camel)
	camel = strings.Replace(camel, " ", "", -1)

	return camel
}

// Search for a wildcard segment and check the name for invalid characters.
// Returns -1 as index, if no wildcard was found.
func FindWildcard(path string) (wildcard string, i int, valid bool) {
	// Find start
	for start, c := range []byte(path) {
		// A wildcard starts with ':' (param) or '*' (catch-all)
		if c != ':' && c != '*' {
			continue
		}

		// Find end and check for invalid characters
		valid = true
		for end, c := range []byte(path[start+1:]) {
			switch c {
			case '/':
				return path[start : start+1+end], start, valid
			case ':', '*':
				valid = false
			}
		}
		return path[start:], start, valid
	}
	return "", -1, false
}

func FindParams(path string) map[string]struct{} {
	params := make(map[string]struct{})
	for path != "" {
		// Find prefix until first wildcard
		wildcard, i, valid := FindWildcard(path)
		if i < 0 { // No wildcard found
			break
		}

		// The wildcard name must not contain ':' and '*'
		if !valid {
			panic("only one wildcard per path segment is allowed, has: '" +
				wildcard + "' in path '" + path + "'")
		}

		// check if the wildcard has a name
		if len(wildcard) < 2 {
			panic("wildcards must be named with a non-empty name in path '" + path + "'")
		}

		path = path[i:]

		if len(wildcard) > len(path) {
			break
		}
		path = path[len(wildcard):]
		params[wildcard] = struct{}{}
	}
	return params
}

func lastChar(str string) uint8 {
	if str == "" {
		panic("The length of the string can't be 0")
	}
	return str[len(str)-1]
}
