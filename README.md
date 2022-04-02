# ginapi
> 类似protobuf的proto语法

## 安装
安装 ginapi

```
go install github.com/liaoyijun/ginapi
```

根据DSL生成你的项目:

```
ginapi --out=project/ example.ginapi
```

DSL示例：
example.ginapi

```
package v1;

host = "http://localhost:8080";

router User("/") {
  post Upload("upload", UploadRequest) returns (UploadResponse);
  put Save("save/:id",SaveRequest) returns (SaveResponse);
}

message UploadRequest {
  file avatar = "form:avatar";
  string name = "form:name";
}

message UploadResponse {
  repeated string results = "results";
}

message SaveRequest {
  int64 id = "uri:id";
  string name = "form:name";
  map<int64,Person> person = "form:person";
}

message Person {
  int64 age = "form:age";
  int64 level = "form:level";
}

message SaveResponse {
  repeated string results = "results";
}
```

## Features
只支持了JSON API
- [√] GET
- [√] HEAD
- [√] POST
- [√] OPTIONS
- [√] PUT
- [√] DELETE
- [√] TRACE
- [√] CONNECT