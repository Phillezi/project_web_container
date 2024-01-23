package main

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func DBconnect(db *App) bool {
	clientOptions := options.Client().ApplyURI(db.config.Mongo.URI + "/" + db.config.Mongo.Database)
	db.client, _ = mongo.Connect(context.TODO(), clientOptions)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := db.client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Failed to ping MongoDB: ", err)
		return false
	}
	return true
}

func DBgetCollections(db *App) bool {
	db.memberCollection = db.client.Database(db.config.Mongo.Database).Collection("member")
	db.contentCollection = db.client.Database(db.config.Mongo.Database).Collection("content")
	db.userCollection = db.client.Database(db.config.Mongo.Database).Collection("user")
	return true
}

func DBdisconnect(db *App) bool {
	if err := db.client.Disconnect(context.TODO()); err != nil {
		log.Fatal("Failed to disconnect from MongoDB:", err)
		return false
	}
	return true
}
