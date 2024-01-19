package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"io/ioutil"
	"time"
	"log"
	"strings"
	"strconv"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"path/filepath"
)

type Member struct {
	ID     string `json:"id" bson:"_id,omitempty"`
	Name   string `json:"name" bson:"name"`
	ImageURL string `json:"image_url" bson:"image_url"`
	About  map[string]string `json:"about" bson:"about"`
	Skills []Skill `json:"skills" bson:"skills"`
	Links  []Link `json:"links" bson:"links"`
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

//----------------- <TEXTCONTENT>
type TextContent struct {
    ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Section string 				`json:"section" bson:"section,omitempty"`
    Language string             `json:"language" bson:"language,omitempty"`
    Title    string             `json:"title" bson:"title,omitempty"`
    Paragraphs []string         `json:"paragraphs" bson:"paragraphs,omitempty"`
}
//----------------- </TEXTCONTENT>

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
	client     *mongo.Client
	memberCollection *mongo.Collection
	contentCollection *mongo.Collection
	userCollection *mongo.Collection
	config     Config
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
	client, _ = mongo.Connect(context.TODO(), clientOptions)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
		return
	}

	fmt.Println("Connected to MongoDB!")

	memberCollection = client.Database(config.Mongo.Database).Collection("member")
	contentCollection = client.Database(config.Mongo.Database).Collection("content")
	userCollection = client.Database(config.Mongo.Database).Collection("user")
}

// create a user
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

func getMembers(w http.ResponseWriter, r *http.Request) {
	var result []Member

	cur, err := memberCollection.Find(context.Background(), bson.D{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cur.Close(context.Background())

	for cur.Next(context.Background()) {
		var member Member
		err := cur.Decode(&member)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result = append(result, member)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func replaceNullValues(member *Member) {
    if member.Skills == nil {
        member.Skills = []Skill{}
    }
    if member.Links == nil {
        member.Links = []Link{}
    }
    if member.About == nil {
        member.About = make(map[string]string)
    }
}

func createMember(w http.ResponseWriter, r *http.Request) {
	var newMember Member
	err := json.NewDecoder(r.Body).Decode(&newMember)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	replaceNullValues(&newMember)

	newMember.CreatedBy, err = getUserIDFromReqToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	_, err = memberCollection.InsertOne(context.Background(), newMember)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newMember)
}

func deleteMember(w http.ResponseWriter, r *http.Request) {
	var requestBody map[string]string

	// Parse the request body
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Extract the member ID from the request body
	memberID, ok := requestBody["id"]
	if !ok {
		http.Error(w, "Member ID is missing in the request body", http.StatusBadRequest)
		return
	}

	// Validate and convert the member ID to MongoDB ObjectId
	memberID_ObjID, err := primitive.ObjectIDFromHex(memberID)
	if err != nil {
		http.Error(w, "Invalid member ID", http.StatusBadRequest)
		return
	}

	var member Member

	// Find the document by _id and decode it into the member variable
	memberCollection.FindOne(context.Background(), bson.M{"_id": memberID_ObjID}).Decode(&member)

	// Check if the user is the owner of the member
	userID, err := getUserIDFromReqToken(r)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	if member.CreatedBy != userID {
		http.Error(w, "You are not the owner of that member!", http.StatusBadRequest)
		return
	}

	// Delete the member from the collection
	result, err := memberCollection.DeleteOne(context.Background(), bson.M{"_id": memberID_ObjID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if a document was deleted
	if result.DeletedCount == 0 {
		http.Error(w, "Member not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Member deleted successfully"})
}


/*
	Handler for GET /api/content
*/
func getContent(w http.ResponseWriter, r *http.Request) {
	var result []TextContent

	cur, err := contentCollection.Find(context.Background(), bson.D{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cur.Close(context.Background())

	for cur.Next(context.Background()) {
		var content TextContent
		err := cur.Decode(&content)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result = append(result, content)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

/*
	Handler for POST /api/content
*/
func createContent(w http.ResponseWriter, r *http.Request) {
	var newContent TextContent
	err := json.NewDecoder(r.Body).Decode(&newContent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if newContent.Language == "" || newContent.Title == "" {
		http.Error(w, "Language and Title are required fields", http.StatusBadRequest)
		return
	}

	insertResult, err := contentCollection.InsertOne(context.Background(), newContent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newContent.ID = insertResult.InsertedID.(primitive.ObjectID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newContent)
}


/*
	Handler for POST /api/login
*/
func loginUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	var user User
	err := userCollection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found in database", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.UserID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	//fmt.Printf("User: " + user.UserID + " " + user.Username + " " + user.Password + "\n")

	tokenString, err := token.SignedString([]byte(config.Server.SecretKey))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

/*
	Handler to serve build
*/
func serveBuild(w http.ResponseWriter, r *http.Request) {
	// Get the requested file path from the URL path
	filePath := r.URL.Path
	//fmt.Printf("REQ: " + filePath + "\n")
	// If the requested file path has no extension, serve the index.html file
	if filepath.Ext(filePath) == "" {
		filePath = "index.html"
	}

	// Construct the full file path
	fullPath := filepath.Join("build", filePath)

	// Serve the file
	http.ServeFile(w, r, fullPath)
}

/*
	Handler for GET /edit
*/
func mainPage(w http.ResponseWriter, r *http.Request) {
	htmlContent, err := ioutil.ReadFile("static/edit.html")
	if err != nil {
		http.Error(w, "Failed to read edit.html", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	w.Write(htmlContent)
}

/*
	Handler for GET /login2
*/
func loginPage(w http.ResponseWriter, r *http.Request) {
	htmlContent, err := ioutil.ReadFile("static/login.html")
	if err != nil {
		http.Error(w, "Failed to read login.html", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	w.Write(htmlContent)
}

func getUserIDFromReqToken(r *http.Request) (primitive.ObjectID, error) {
    tokenString, err := getTokenFromRequest(r)
    if err != nil {
        return primitive.NilObjectID, fmt.Errorf("token not found")
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Verify the signing method and return the secret key
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method")
        }
        return []byte(config.Server.SecretKey), nil
    })
    if err != nil || !token.Valid {
        return primitive.NilObjectID, fmt.Errorf("invalid or expired token")
    }

    userID, ok := token.Claims.(jwt.MapClaims)["user_id"].(string)
    if !ok {
        return primitive.NilObjectID, fmt.Errorf("token user_id not found")
    }

    userIDObjID, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return primitive.NilObjectID, fmt.Errorf("could not create ObjectID from user ID string")
    }

    return userIDObjID, nil
}

/*
	Extracts the Auth token from the request.
*/
func getTokenFromRequest(r *http.Request) (string, error) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return "", fmt.Errorf("token not found")
	}

	// Check if the Authorization header has the "Bearer " prefix
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(tokenString, bearerPrefix) {
		return "", fmt.Errorf("invalid token format; expected 'Bearer' prefix")
	}

	// Remove the "Bearer " prefix
	return tokenString[len(bearerPrefix):], nil
}

/*
	Authenticate the Auth token.
*/
func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := getTokenFromRequest(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verify the signing method and return the secret key
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(config.Server.SecretKey), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		userID, ok := token.Claims.(jwt.MapClaims)["user_id"].(string)
        if !ok {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
	
		userID_ObjID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			http.Error(w, "Could not parse userID", http.StatusUnauthorized)
            return
		}

        var user User
        err = userCollection.FindOne(context.Background(), bson.M{"_id": userID_ObjID}).Decode(&user)
        if err != nil {
			log.Println("Error finding user:", err)
            http.Error(w, "User not found in database", http.StatusUnauthorized)
            return
        }

		// Token is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

/*
	Middleware to allow CORS
*/
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

func main() {
	username_ := os.Getenv("WEB_USERNAME")
    password_ := os.Getenv("WEB_PASSWORD")
	if username_ != "" && password_ != "" {
		err := createUser(username_, password_)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
	

	r := mux.NewRouter()

	r.Use(corsMiddleware)

	authRouter := r.PathPrefix("/api/add").Subrouter()
	authRouter.Use(authenticateMiddleware)
	authRouter.HandleFunc("/content", createContent).Methods("POST")
    authRouter.HandleFunc("/member", createMember).Methods("POST")

	authRouter2 := r.PathPrefix("/api/del").Subrouter();
	authRouter2.HandleFunc("/member", deleteMember).Methods("POST")

	r.HandleFunc("/api/member", getMembers).Methods("GET")
    r.HandleFunc("/api/content", getContent).Methods("GET")

	r.HandleFunc("/edit", mainPage).Methods("GET")
	r.HandleFunc("/login2", loginPage).Methods("GET")
	r.HandleFunc("/api/login", loginUser).Methods("POST")

	r.HandleFunc("/{path:.*}", serveBuild).Methods("GET")
    
	defer func() {
        if err := client.Disconnect(context.TODO()); err != nil {
            log.Fatal("Failed to disconnect from MongoDB:", err)
        }
    }()

    port := fmt.Sprintf(":%d", config.Server.Port)
    fmt.Printf("Server is listening on %s...\n", port)
    http.ListenAndServe(port, r)
}