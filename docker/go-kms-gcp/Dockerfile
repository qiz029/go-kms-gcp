FROM golang
MAINTAINER todd.zheng

RUN go get github.com/qiz029/go-kms-gcp
WORKDIR $GOPATH/github.com/qiz029/go-kms-gcp

## need the gcp cred to be exported here

EXPOSE 9999

ENTRYPOINT [ "go run web.go" ]