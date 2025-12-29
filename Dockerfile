FROM golang:1.25-alpine

RUN apk add --no-cache libpcap-dev gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

CMD ["go", "run", "./cmd/GoSniffer"]