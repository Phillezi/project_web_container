package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func ServeBuild(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Path

	if filepath.Ext(filePath) == "" {
		filePath = "index.html"
	}

	fullPath := filepath.Join("build", filePath)

	http.ServeFile(w, r, fullPath)
}

func ServeImage(w http.ResponseWriter, r *http.Request) {
	filePath := strings.TrimPrefix(r.URL.Path, "/images/")
	fullPath := filepath.Join("images", filePath)
	http.ServeFile(w, r, fullPath)
}

func PollHealth(w http.ResponseWriter, r *http.Request, app *App) {
	if app.IsOk() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service Unavailable"))
	}
}

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

func AddContent(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "POST content not impl\n\r")
}

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

func AddMember(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "POST member not impl\n\r")
}

func LoginUser(w http.ResponseWriter, r *http.Request, app App) {
	username := r.FormValue("username")
	password := r.FormValue("password")

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
