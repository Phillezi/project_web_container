package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

/*
A handler that serves the files in the build directory.
*/
func ServeBuild(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Path

	if filepath.Ext(filePath) == "" {
		filePath = "index.html"
	}

	fullPath := filepath.Join("build", filePath)

	http.ServeFile(w, r, fullPath)
}

/*
A handler that serves the files in the image directory.
*/
func ServeImage(w http.ResponseWriter, r *http.Request) {
	filePath := strings.TrimPrefix(r.URL.Path, "/images/")
	fullPath := filepath.Join("images", filePath)
	http.ServeFile(w, r, fullPath)
}

/*
A handler that checks the health of the application and then responds with the status.
*/
func PollHealth(w http.ResponseWriter, r *http.Request, app *App) {
	if app.IsOk() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service Unavailable"))
	}
}

/*
A handler that serves the content from the mongodb content collection.
*/
func ServeContent(w http.ResponseWriter, r *http.Request, contentCollection *mongo.Collection) {
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
A handler for post requests to add content in the database. TODO: Implement
*/
func AddContent(w http.ResponseWriter, r *http.Request) {
	go func(ip string) {
		fmt.Printf("%s : Post Content req from IP:%s\n", time.Now().Format(time.RFC3339), ip)
	}(getIPAddress(r))
	fmt.Fprint(w, "POST content not impl\n\r")
}

/*
A handler that serves the members from the mongodb member collection.
*/
func ServeMember(w http.ResponseWriter, r *http.Request, memberCollection *mongo.Collection) {
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

/*
A handler for post requests to add members in the database. TODO: Implement
*/
func AddMember(w http.ResponseWriter, r *http.Request) {
	go func(ip string) {
		fmt.Printf("%s : Post Member req from IP:%s\n", time.Now().Format(time.RFC3339), ip)
	}(getIPAddress(r))
	fmt.Fprint(w, "POST member not impl\n\r")
}

/*
A handler for logging in, sends a JWT token on successful login.
*/
func LoginUser(w http.ResponseWriter, r *http.Request, app App) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	go func(username string, ipaddr string) {
		fmt.Printf("%s : Login attempt: -u:%s, IP:%s\n", time.Now().Format(time.RFC3339), username, ipaddr)
	}(username, getIPAddress(r))

	var user User
	err := app.userCollection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found in database", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	tokenString, err := createToken(username, app)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

/*
Helper function to get the IP address of a http request.
*/
func getIPAddress(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}
	}
	return ip
}
