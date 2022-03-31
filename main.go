// ginapi --out=./example/routes/user/v1/ ./example/example.ginapi
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
	"github.com/dave/jennifer/jen"
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

func (r *RouterEntry) CallBlock() []jen.Code {
	// todo `HEAD` `POST` `OPTIONS` `PUT` `DELETE` `TRACE` `CONNECT`
	blocks := r.Route.ShouldBindBlock()
	blocks = append(blocks,
		jen.Id("resp").Op(",").Id("err").Op(":=").Id(fmt.Sprintf("%s.%s", "service", r.Route.Name)).Call(
			jen.Id("ctx"),
			jen.Op("&").Id("req"),
		),
		jen.If(
			jen.Err().Op("!=").Nil(),
		).Block(
			jen.Id("ctx.Render").Call(
				jen.Id("200"),
				jen.Id("render.Error").Call(
					jen.Id("err"),
				),
			),
			jen.Return(),
		),
		jen.Id("ctx.Render").Call(
			jen.Id("200"),
			jen.Id("render.Success").Call(
				jen.Id("resp"),
			),
		),
	)
	return []jen.Code{
		// jen.Id(r.Route.Path),
		jen.Func().Params(
			jen.Id("ctx").Id("*gin.Context"),
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

func (route *Route) ShouldBindBlock() []jen.Code {
	codes := []jen.Code{
		jen.Var().Id("req").Id(route.Request.Reference),
	}
	params := route.ParseUri()
	if len(params) > 0 {
		codes = append(codes, jen.If(
			jen.Err().Op(":=").Id("ctx.ShouldBindUri").Call(
				jen.Op("&").Id("req"),
			),
			jen.Err().Op("!=").Nil(),
		).Block(
			jen.Id("ctx.Render").Call(
				jen.Id("200"),
				jen.Id("render.Error").Call(
					jen.Id("err"),
				),
			),
			jen.Return(),
		))
	}
	codes = append(codes, jen.If(
		jen.Err().Op(":=").Id("ctx.ShouldBind").Call(
			jen.Op("&").Id("req"),
		),
		jen.Err().Op("!=").Nil(),
	).Block(
		jen.Id("ctx.Render").Call(
			jen.Id("200"),
			jen.Id("render.Error").Call(
				jen.Id("err"),
			),
		),
		jen.Return(),
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

func (message *Message) Uri() jen.Dict {
	params := make(jen.Dict)
	for _, v := range message.Entries {
		if v.Field.HasTag("uri") {
			switch v.Field.Type.Scalar {
			case Int32, Int64, Uint32, Uint64, Sint32, Sint64, Fixed32, Fixed64, SFixed32, SFixed64:
				params[jen.Lit(v.Field.Name)] = jen.Id("fmt.Sprintf").Call(
					jen.Lit("%d"),
					jen.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case Float, Double:
				params[jen.Lit(v.Field.Name)] = jen.Id("fmt.Sprintf").Call(
					jen.Lit("%f"),
					jen.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case Bool:
				params[jen.Lit(v.Field.Name)] = jen.Id("fmt.Sprintf").Call(
					jen.Lit("%t"),
					jen.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case String:
				params[jen.Lit(v.Field.Name)] = jen.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name)))
			}
		}
	}
	return params
}

func (message *Message) Form() jen.Dict {
	params := make(jen.Dict)
	for _, v := range message.Entries {
		if v.Field.HasTag("form") && v.Field.Type.Scalar == File {
			switch v.Field.Type.Scalar {
			case Int32, Int64, Uint32, Uint64, Sint32, Sint64, Fixed32, Fixed64, SFixed32, SFixed64:
				params[jen.Lit(v.Field.Name)] = jen.Id("fmt.Sprintf").Call(
					jen.Lit("%d"),
					jen.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case Float, Double:
				params[jen.Lit(v.Field.Name)] = jen.Id("fmt.Sprintf").Call(
					jen.Lit("%f"),
					jen.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case Bool:
				params[jen.Lit(v.Field.Name)] = jen.Id("fmt.Sprintf").Call(
					jen.Lit("%t"),
					jen.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name))),
				)
			case String:
				params[jen.Lit(v.Field.Name)] = jen.Id(fmt.Sprintf("req.%s", ToCamelCase(v.Field.Name)))
			}
		}
	}
	return params
}

func (message *Message) File() []jen.Code {
	var codes []jen.Code
	for _, v := range message.Entries {
		if v.Field.Type.Scalar == File {
			_temp := "_" + v.Field.Name
			codes = append(
				codes,
				jen.Id(_temp).Op(",").Err().Op(":=").Id("req").Op(".").Id(ToCamelCase(v.Field.Name)).Op(".").Id("Open").Call(),
				jen.If(
					jen.Err().Op("!=").Nil(),
				).Block(
					jen.Return(
						jen.Id("nil"),
						jen.Id("err"),
					),
				),
				jen.Id("r.SetFileReader").Call(
					jen.Id("\""+v.Field.Name+"\""),
					jen.Id("req").Op(".").Id(ToCamelCase(v.Field.Name)).Op(".").Id("Filename"),
					jen.Id(_temp),
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

func (field *Field) Statement() jen.Code {
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

func (scalar Scalar) String() string {
	switch scalar {
	case String:
		return "string"
	case Int32, Sint32, SFixed32:
		return "int32"
	case Int64, Sint64, SFixed64:
		return "int64"
	case Uint32, Fixed32:
		return "uint32"
	case Uint64, Fixed64:
		return "uint64"
	case Float:
		return "float32"
	case Double:
		return "float64"
	case Bool:
		return "bool"
	case Bytes:
		return "[]byte"
	default:
		return ""
	}
}

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

type ScalarStatementOption func(*Field) jen.Code

func StringStatement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		if field.Repeated {
			return jen.Id(ToCamelCase(field.Name)).Op("[]").String().Tag(field.Tags())
		} else {
			return jen.Id(ToCamelCase(field.Name)).String().Tag(field.Tags())
		}
	}
}

func Int32Statement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		if field.Repeated {
			return jen.Id(ToCamelCase(field.Name)).Op("[]").Int32().Tag(field.Tags())
		} else {
			return jen.Id(ToCamelCase(field.Name)).Int32().Tag(field.Tags())
		}
	}
}

func Int64Statement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		if field.Repeated {
			return jen.Id(ToCamelCase(field.Name)).Op("[]").Int64().Tag(field.Tags())
		} else {
			return jen.Id(ToCamelCase(field.Name)).Int64().Tag(field.Tags())
		}
	}
}

func Uint32Statement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		if field.Repeated {
			return jen.Id(ToCamelCase(field.Name)).Op("[]").Uint32().Tag(field.Tags())
		} else {
			return jen.Id(ToCamelCase(field.Name)).Uint32().Tag(field.Tags())
		}
	}
}

func Uint64Statement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		if field.Repeated {
			return jen.Id(ToCamelCase(field.Name)).Op("[]").Uint64().Tag(field.Tags())
		} else {
			return jen.Id(ToCamelCase(field.Name)).Uint64().Tag(field.Tags())
		}
	}
}

func FloatStatement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		if field.Repeated {
			return jen.Id(ToCamelCase(field.Name)).Op("[]").Float32().Tag(field.Tags())
		} else {
			return jen.Id(ToCamelCase(field.Name)).Float32().Tag(field.Tags())
		}
	}
}

func DoubleStatement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		if field.Repeated {
			return jen.Id(ToCamelCase(field.Name)).Op("[]").Float64().Tag(field.Tags())
		} else {
			return jen.Id(ToCamelCase(field.Name)).Float64().Tag(field.Tags())
		}
	}
}

func BoolStatement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		if field.Repeated {
			return jen.Id(ToCamelCase(field.Name)).Op("[]").Bool().Tag(field.Tags())
		} else {
			return jen.Id(ToCamelCase(field.Name)).Bool().Tag(field.Tags())
		}
	}
}

func BytesStatement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		return jen.Id(ToCamelCase(field.Name)).Op("[]").Byte().Tag(field.Tags())
	}
}

func FileStatement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		return jen.Id(ToCamelCase(field.Name)).Op("*").Qual("mime/multipart", "FileHeader").Tag(field.Tags())
	}
}

func NoneStatement() ScalarStatementOption {
	return func(field *Field) jen.Code {
		if field.Type.Map != nil {
			key, value := field.Type.Map.KeyValue()
			return jen.Id(ToCamelCase(field.Name)).Map(jen.Id(key)).Id(value).Tag(field.Tags())
		} else {
			if field.Repeated {
				return jen.Id(ToCamelCase(field.Name)).Op("[]*").Id(field.Type.Reference).Tag(field.Tags())
			} else {
				return jen.Id(ToCamelCase(field.Name)).Op("*").Id(field.Type.Reference).Tag(field.Tags())
			}
		}
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
	None:     NoneStatement(),
}

func (s Scalar) ScalarStatement(field *Field) jen.Code {
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

func (mt *MapType) KeyValue() (string, string) {
	var key string
	if mt.Key.Reference != "" {
		key = "*" + mt.Key.Reference
	} else {
		key = mt.Key.Scalar.String()
	}
	var value string
	if mt.Value.Reference != "" {
		value = "*" + mt.Value.Reference
	} else {
		value = mt.Value.Scalar.String()
	}

	return key, value
}

var (
	parser = participle.MustBuild(&Ginapi{}, participle.UseLookahead(2))

	cli struct {
		Out  string `help:"out."`
		Path string `arg`
	}
)

type Generator struct {
	File  *jen.File
	Value *Ginapi
}

func NewGenerator(file *jen.File, value *Ginapi) *Generator {
	return &Generator{
		File:  file,
		Value: value,
	}
}

func (g *Generator) ServiceInterface() {
	keyword := fmt.Sprintf("%s%s", g.Value.Router().Name, "Service")
	statement := g.File.Type().Id(keyword)
	var methods []jen.Code
	for _, r := range g.Value.Router().Entries {
		methods = append(methods, jen.Id(r.Route.Name).Params(
			jen.Id("ctx").Op("*").Qual("github.com/gin-gonic/gin", "Context"),
			jen.Id("req").Op("*").Id(r.Route.Request.Reference),
		).Params(
			jen.Op("*").Id(r.Route.Response.Reference),
			jen.Id("error"),
		))
	}
	statement.Interface(methods...).Line()
}

func (g *Generator) ClientInterface() {
	g.File.Type().Id("RequestOption").Func().Params(
		jen.Op("*").Qual("github.com/go-resty/resty/v2", "Request"),
	).Line()

	keyword := fmt.Sprintf("%s%s", g.Value.Router().Name, "Client")
	statement := g.File.Type().Id(keyword)
	var methods []jen.Code
	for _, r := range g.Value.Router().Entries {
		methods = append(methods, jen.Id(r.Route.Name).Params(
			jen.Id("ctx").Qual("context", "Context"),
			jen.Id("req").Op("*").Id(r.Route.Request.Reference),
			jen.Id("opts").Op("...").Id("RequestOption"),
		).Params(
			jen.Op("*").Id(r.Route.Response.Reference),
			jen.Id("error"),
		))
	}
	statement.Interface(methods...).Line()
}

func (g *Generator) RenderInterface() {
	g.File.Type().Id("Render").Interface(
		jen.Id("Error").Params(jen.Id("error")).Params(jen.Qual("github.com/gin-gonic/gin/render", "Render")),
		jen.Id("Success").Params(jen.Id("interface{}")).Params(jen.Qual("github.com/gin-gonic/gin/render", "Render")),
		jen.Id("Unmarshal").Params(
			jen.Id("[]byte"),
			jen.Id("int"),
			jen.Id("interface{}"),
		).Params(jen.Id("error")),
	).Line()
}

func (g *Generator) RegisterService() {
	keyword := fmt.Sprintf("%s%s", g.Value.Router().Name, "Service")
	register := g.File.Func().Id("RegisterService").Params(
		jen.Id("engine").Op("*").Qual("github.com/gin-gonic/gin", "Engine"),
		jen.Id("service").Id(keyword),
		jen.Id("render").Id("Render"),
		jen.Id("middleware").Op("...").Qual("github.com/gin-gonic/gin", "HandlerFunc"),
	)

	var block []jen.Code
	if g.Value.Group() != "\"/\"" {
		block = append(block, jen.Id("group").Op(":=").Id("engine").Dot("Group").Call(
			jen.Id(g.Value.Group()),
			jen.Id("middleware..."),
		))
		var routers []jen.Code
		for _, r := range g.Value.Router().Entries {
			call := []jen.Code{
				jen.Id(r.Route.Path),
			}
			call = append(call, r.CallBlock()...)
			routers = append(routers, jen.Id("group").Dot(strings.ToUpper(r.Route.Method)).Call(call...))
		}
		block = append(block, jen.Block(routers...))
	} else {
		for _, r := range g.Value.Router().Entries {
			call := []jen.Code{
				jen.Id(r.Route.Path),
			}
			call = append(call, jen.Append(
				jen.Index().Qual("github.com/gin-gonic/gin", "HandlerFunc").Values(
					r.CallBlock()...,
				),
				jen.Id("middleware..."),
			).Op("..."))
			block = append(block, jen.Id("engine").Dot(strings.ToUpper(r.Route.Method)).Call(call...))
		}
	}

	register.Block(block...).Line()
}

func (g *Generator) MessageStruct() {
	for _, m := range g.Value.Messages() {
		var fields []jen.Code
		for _, f := range m.Entries {
			fields = append(fields, f.Field.Statement())
		}
		g.File.Type().Id(m.Name).Struct(fields...).Line()
	}
}

func (g *Generator) ClientImplement() {
	client := fmt.Sprintf("%s%s", strings.ToLower(g.Value.Router().Name), "Client")
	g.File.Type().Id(client).Struct(
		jen.Id("scheme").String(),
		jen.Id("host").String(),
		jen.Id("client").Op("*").Qual("github.com/go-resty/resty/v2", "Client"),
		jen.Id("render").Id("Render"),
	).Line()
	g.File.Type().Id("clientOption").Func().Params(
		jen.Op("*").Id(client),
	).Line()
	g.File.Func().Id("WithScheme").Params(
		jen.Id("scheme").String(),
	).Params(
		jen.Id("clientOption"),
	).Block(
		jen.Return(
			jen.Func().Params(
				jen.Id("c").Op("*").Id(client),
			).Block(
				jen.Id("c").Op(".").Id("scheme").Op("=").Id("scheme"),
			),
		),
	).Line()
	g.File.Func().Id("WithHost").Params(
		jen.Id("host").String(),
	).Params(
		jen.Id("clientOption"),
	).Block(
		jen.Return(
			jen.Func().Params(
				jen.Id("c").Op("*").Id(client),
			).Block(
				jen.Id("c").Op(".").Id("host").Op("=").Id("host"),
			),
		),
	).Line()
	g.File.Func().Id("WithClient").Params(
		jen.Id("client").Op("*").Qual("net/http", "Client"),
	).Params(
		jen.Id("clientOption"),
	).Block(
		jen.Return(
			jen.Func().Params(
				jen.Id("c").Op("*").Id(client),
			).Block(
				jen.Id("c").Op(".").Id("client").Op("=").Qual("github.com/go-resty/resty/v2", "NewWithClient").Call(
					jen.Id("client"),
				),
			),
		),
	).Line()

	implement := fmt.Sprintf("%s%s", g.Value.Router().Name, "Client")
	_url, err := url.Parse(strings.Trim(g.Value.Host(), "\""))
	if err != nil {
		panic(err)
	}
	g.File.Func().Id(fmt.Sprintf("New%s", implement)).Params(
		jen.Id("render").Id("Render"),
		jen.Id("opts").Op("...").Id("clientOption"),
	).Params(
		jen.Id(implement),
	).Block(
		jen.Id("c").Op(":=").Id(client).Values(jen.Dict{
			jen.Id("scheme"): jen.Lit(_url.Scheme),
			jen.Id("host"):   jen.Lit(_url.Host),
			jen.Id("client"): jen.Qual("github.com/go-resty/resty/v2", "NewWithClient").Call(
				jen.Qual("net/http", "DefaultClient"),
			),
			jen.Id("render"): jen.Id("render"),
		}),
		jen.For(
			jen.Id("_").Op(",").Id("o").Op(":=").Range().Id("opts").Block(
				jen.Id("o").Call(
					jen.Op("&").Id("c"),
				),
			),
		),
		jen.Return(
			jen.Op("&").Id("c"),
		),
	).Line()
	g.MethodStatement(client)
}

func (g *Generator) MethodStatement(client string) {
	for _, r := range g.Value.Router().Entries {
		var statements []jen.Code

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
			jen.Id("c").Op("*").Id(client),
		).Id(r.Route.Name).Params(
			jen.Id("ctx").Qual("context", "Context"),
			jen.Id("req").Op("*").Id(r.Route.Request.Reference),
			jen.Id("opts").Op("...").Id("RequestOption"),
		).Params(
			jen.Op("*").Id(r.Route.Response.Reference),
			jen.Id("error"),
		).Block(statements...).Line()
	}
}

func (g *Generator) ParamsCode(method string, path string, req string, resp string) []jen.Code {
	uri := make(jen.Dict)
	form := make(jen.Dict)
	file := []jen.Code{}
	for _, message := range g.Value.Messages() {
		if message.Name == req {
			uri = message.Uri()
			form = message.Form()
			file = message.File()
		}
	}
	path = "%s://%s" + path
	statements := []jen.Code{
		jen.Id("url").Op(":=").Qual("fmt", "Sprintf").Call(
			jen.Lit(path),
			jen.Id("c.scheme"),
			jen.Id("c.host"),
		),
		jen.Var().Id("result").Id(resp),
		jen.Id("r").Op(":=").Id("c.client.R()"),
		jen.For(
			jen.Id("_").Op(",").Id("o").Op(":=").Range().Id("opts").Block(
				jen.Id("o").Call(
					jen.Id("r"),
				),
			),
		),
	}
	if len(uri) > 0 {
		statements = append(
			statements,
			jen.Id("r.SetPathParams").Call(
				jen.Map(jen.String()).String().Values(uri),
			),
		)
	}
	if method == "get" {
		if len(form) > 0 {
			statements = append(
				statements,
				jen.Id("r.SetQueryParams").Call(
					jen.Map(jen.String()).String().Values(form),
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
					jen.Id("r.SetFormData").Call(
						jen.Map(jen.String()).String().Values(form),
					),
				)
			}
		} else {
			statements = append(
				statements,
				jen.Id("r.SetBody").Call(
					jen.Id("req"),
				),
			)
		}
	}

	statements = append(
		statements,
		jen.Id("resp").Op(",").Err().Op(":=").Id("r").Op(".").Id(ToCamelCase(strings.Trim(method, "\""))).Call(
			jen.Id("url"),
		),
	)
	statements = append(
		statements,
		jen.If(
			jen.Err().Op("!=").Nil(),
		).Block(
			jen.Return(
				jen.Id("nil"),
				jen.Id("err"),
			),
		),
		jen.If(
			jen.Err().Op(":=").Id("c.render.Unmarshal").Call(
				jen.Id("resp.Body()"),
				jen.Id("resp.StatusCode()"),
				jen.Op("&").Id("result"),
			),
			jen.Err().Op("!=").Nil(),
		).Block(
			jen.Return(
				jen.Id("nil"),
				jen.Id("err"),
			),
		).Else().Block(
			jen.Return(
				jen.Id("&result"),
				jen.Id("nil"),
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

	f0 := jen.NewFile(api.Package())
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
