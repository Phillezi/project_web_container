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

# Set default values for username and password (can be overridden when running the container)
ENV USERNAME=default_user
ENV PASSWORD=default_password

# Run the createuser.go command at startup using environment variables
CMD ["sh", "-c", "go run createuser.go $USERNAME $PASSWORD && ./main"]
