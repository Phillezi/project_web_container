// init-mongo.js

// Connect to the admin database
db = db.getSiblingDB('admin');

// Create an admin user
db.createUser({
    user: 'admin',
    pwd: 'your-mongo-root-password',
    roles: ['root']
});

// Switch to the target database (goDB in this case)
db = db.getSiblingDB('goDB');

// Create the user for the application
db.createUser({
    user: 'go_secret_user',
    pwd: 'go_secret_pass',
    roles: ['readWrite', 'dbAdmin']
});