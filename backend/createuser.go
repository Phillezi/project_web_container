package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"golang.org/x/crypto/bcrypt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	UserID primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username string `json:"username" bson:"username,omitempty"`
	Password string `json:"password" bson:"password,omitempty"`
}

type Config struct {
	Server struct {
		Port int `json:"port"`
		SecretKey string `json:"secret-key"`
	} `json:"server"`
	Mongo struct {
		URI      string `json:"uri"`
		Database string `json:"database"`
	} `json:"mongo"`
}

var (
	client        *mongo.Client
	userCollection *mongo.Collection
	config        Config
)

func init() {
	serverPort := os.Getenv("SERVER_PORT")
    secretKey := os.Getenv("SECRET_KEY")
    mongoURI := os.Getenv("MONGO_URI")
    mongoDB := os.Getenv("MONGO_DB")

    // Set default values if environment variables are not provided
    if serverPort == "" {
        serverPort = "8080"
    }
    if secretKey == "" {
        secretKey = "your-secret-key"
    }
    if mongoURI == "" {
        mongoURI = "mongodb://go_secret_user:go_secret_pass@mongodb:27017"
    }
    if mongoDB == "" {
        mongoDB = "goDB"
    }

    config.Server.Port, _ = strconv.Atoi(serverPort)
    config.Server.SecretKey = secretKey
    config.Mongo.URI = mongoURI
    config.Mongo.Database = mongoDB

	clientOptions := options.Client().ApplyURI(config.Mongo.URI + "/" + config.Mongo.Database)
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
		return
	}

	// Check the connection
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
		return
	}

	fmt.Println("Connected to MongoDB!")

	userCollection = client.Database(config.Mongo.Database).Collection("user")
}

func createUser(username, password string) error {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	result := userCollection.FindOne(context.Background(), bson.M{"username": username})

	var existingUser User
	if err := result.Decode(&existingUser); err == nil {
		fmt.Println("User already exists")
		return fmt.Errorf("Error username already exist")
	} else if err != mongo.ErrNoDocuments {
		return fmt.Errorf("Error searching if user exsists: %v", err)
	} 

	newUser := User{
		Username: username,
		Password: string(hashedPassword),
	}

	_, err = userCollection.InsertOne(context.Background(), newUser)
	if err != nil {
		return fmt.Errorf("failed to insert user into the database: %v", err)
	}

	fmt.Println("User created successfully!")
	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: createuser <username> <password>")
		os.Exit(1)
	}

	username := os.Args[1]
	password := os.Args[2]

	err := createUser(username, password)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := client.Disconnect(context.TODO()); err != nil {
			log.Fatal("Failed to disconnect from MongoDB:", err)
		}
	}()
}
