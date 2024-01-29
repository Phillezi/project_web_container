package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Member struct {
	ID        string             `json:"id" bson:"_id,omitempty"`
	Name      string             `json:"name" bson:"name"`
	ImageURL  string             `json:"image_url" bson:"image_url"`
	About     map[string]string  `json:"about" bson:"about"`
	Skills    []Skill            `json:"skills" bson:"skills"`
	Links     []Link             `json:"links" bson:"links"`
	Contacts  []Contact          `json:"contact" bson:"contact,omitempty"`
	CreatedBy primitive.ObjectID `json:"createdby" bson:"createdby,omitempty"`
}

type Skill struct {
	Name  string `json:"name" bson:"name,omitempty"`
	Level string `json:"level" bson:"level,omitempty"`
}

type Link struct {
	Name string `json:"name" bson:"name,omitempty"`
	URL  string `json:"url" bson:"url,omitempty"`
}

type Contact struct {
	Name string `json:"name" bson:"name,omitempty"`
	Value  string `json:"value" bson:"value,omitempty"`
}

type TextContent struct {
	ID         primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Section    string             `json:"section" bson:"section,omitempty"`
	Language   string             `json:"language" bson:"language,omitempty"`
	Title      string             `json:"title" bson:"title,omitempty"`
	Paragraphs []string           `json:"paragraphs" bson:"paragraphs,omitempty"`
}

type User struct {
	UserID   primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username string             `json:"username" bson:"username,omitempty"`
	Password string             `json:"password" bson:"password,omitempty"`
}

type Config struct {
	Server struct {
		Port      int    `json:"port"`
		SecretKey string `json:"secret-key"`
	} `json:"server"`
	Mongo struct {
		URI      string `json:"uri"`
		Database string `json:"database"`
	} `json:"mongo"`
}

type App struct {
	client            *mongo.Client
	memberCollection  *mongo.Collection
	contentCollection *mongo.Collection
	userCollection    *mongo.Collection
	config            Config
	server            *http.Server
	dbConnected 	  bool
}

func (app *App) initialize() {
	if serverPort := os.Getenv("SERVER_PORT"); serverPort != "" {
		if port, err := strconv.Atoi(serverPort); err == nil {
			app.config.Server.Port = port
		} else {
			fmt.Println("Error parsing SERVER_PORT as an integer:", err)
			app.config.Server.Port = 8080 // Use a default value
		}
	} else {
		fmt.Println("SERVER_PORT not set. Using default port: 8080")
		app.config.Server.Port = 8080
	}

	app.config.Server.SecretKey = os.Getenv("SECRET_KEY")
	if app.config.Server.SecretKey == "" {
		fmt.Println("SECRET_KEY not set. Using default secret key: your-secret-key")
		app.config.Server.SecretKey = "your-secret-key"
	}

	app.config.Mongo.URI = os.Getenv("MONGO_URI")
	if app.config.Mongo.URI == "" {
		fmt.Println("MONGO_URI not set. Using default URI: mongodb://go_secret_user:go_secret_pass@mongodb:27017")
		app.config.Mongo.URI = "mongodb://go_secret_user:go_secret_pass@mongodb:27017"
	}

	app.config.Mongo.Database = os.Getenv("MONGO_DB")
	if app.config.Mongo.Database == "" {
		fmt.Println("MONGO_DB not set. Using default database: goDB")
		app.config.Mongo.Database = "goDB"
	}

	if DBconnect(app) {
		fmt.Println("Connected to the database")
		app.dbConnected = true
		DBgetCollections(app)
	} else {
		fmt.Println("Could not connect to the database...")
		app.dbConnected = false
	}

}

func (app *App) close() {
	if DBdisconnect(app) {
		fmt.Println("Disconnected from database")
		app.dbConnected = false
	}

}

func (app *App) IsOk() bool {
    return app.dbConnected
}
