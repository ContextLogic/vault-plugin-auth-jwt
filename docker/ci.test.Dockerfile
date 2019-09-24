FROM golang:1.12-stretch
ENV GOPATH /go

# install git
RUN apt-get update
RUN apt-get install git

# install golint
RUN go get -u golang.org/x/lint/golint

