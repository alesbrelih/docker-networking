FROM golang:1.22

WORKDIR /app

RUN apt-get update && \
	apt-get install -y tcpdump net-tools

COPY go.mod .
COPY main.go .

RUN go build -o main .

CMD ["./main"]

