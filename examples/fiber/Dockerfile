FROM golang:1.21-alpine

WORKDIR /src/fiber-nextauth
COPY . .
RUN go mod download

WORKDIR /src/fiber-nextauth/examples/fiber
RUN go mod edit -replace github.com/kiwamizamurai/fiber-nextauth=/src/fiber-nextauth && \
    go mod tidy && \
    go build -o main .

EXPOSE 3000

CMD ["./main"]
