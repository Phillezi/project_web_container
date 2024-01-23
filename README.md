# Project Web Container

This repository contains a Docker Compose setup for a web-app for a project pitch site with a go backend container and MongoDB container.

Note: This project is a personal exploration/learning of Docker and Go, and I have minimal prior experience with both technologies. Therfore especially the backend may contain security flaws and oversights aswell as not so clean code.

## Requirements
- Docker

## Instructions

### Clone this repository
```bash
git clone git@github.com:Phillezi/project_web_container.git
cd project_web_container
```

### Start the containers
```bash
docker-compose up -d
```
Alternatively you can configure your enviroment variables here by setting the ones you want to change here.
For example:
```bash
docker-compose up -d MONGO_DB=DATABASE_NAME
```
[Check Configuration](#configuration) to see how you can configure the deployment.

This command will build and start the Docker containers in detached mode (`-d`).

### Stop and remove the containers
```bash
docker-compose down
```

This command will stop and remove the running containers.

## Configuration

You can customize the configuration by modifying the `docker-compose.yml` file to suit your specific requirements.

### Environment Variables

Ensure to check and modify any environment variables in the `docker-compose.yml` file according to your application's needs.

## Accessing web-app
Access your web application at [http://localhost:8080](http://localhost:8080), or [http://localhost:YOUR_PORT](http://localhost:YOUR_PORT) where `YOUR_PORT` is the port specified in your configuration.
