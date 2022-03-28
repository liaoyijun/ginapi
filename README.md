ginapi
> generator for gin

## Installation
First, install ginapi.

```
go install github.com/liaoyijun/ginapi
```

Then generate your new project:

```
ginapi --out=project/ example.ginapi
```

example.ginapi

```
package v1;

host = "http://localhost:8080";

group = "/school/";

router User {
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
  int64 id = "uri:id"
  string name = "form:name";
}

message SaveResponse {
  repeated string results = "results";
}
```

## Features
- [√] GET
- [√] HEAD
- [√] POST
- [√] OPTIONS
- [√] PUT
- [√] DELETE
- [√] TRACE
- [√] CONNECT