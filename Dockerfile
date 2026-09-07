FROM golang:1.18 AS build
WORKDIR /build
COPY main.go main.go
RUN CGO_ENABLED=0 go build -o main main.go

FROM alpine:3.16.2
WORKDIR /app
EXPOSE 8080
COPY --from=build /build/main main
CMD ["./main"]
