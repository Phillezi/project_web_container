FROM golang:latest

WORKDIR /go/src/app/backend

# Copy only the go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build the application
RUN go build -o main .

EXPOSE 8080

# Run
CMD ["./main"]
