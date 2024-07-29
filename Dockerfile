FROM golang:1.22

WORKDIR /app

COPY go.mod .
COPY main.go .

RUN go build -o main .

CMD ["./main"]

