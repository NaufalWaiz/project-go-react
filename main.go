package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type Todo struct {
	ID        string `json:"id"` // Change to string to match UUID
	Completed bool   `json:"completed"`
	Body      string `json:"body"`
	UserID    string `json:"user_id"` // Change to string to match UUID if UserID is also UUID
	Status    string `json:"status"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

var db *sql.DB
var ctx = context.Background()
var Rdb *redis.Client

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file")
		return
	}

	Rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer Rdb.Close()

	// Test the Redis connection
	if _, err := Rdb.Ping(ctx).Result(); err != nil {
		fmt.Println("connect to Redis BANGGGGGGG")
		fmt.Println("Failed to connect to Redis:", err)
		return
	}

	POSTGRESQL_URI := os.Getenv("POSTGRESQL_URI")
	db, err = sql.Open("pgx", POSTGRESQL_URI)
	if err != nil {
		fmt.Println("PostgreSQL Connection Error:", err)
		return
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		fmt.Println("PostgreSQL Ping Error:", err)
		return
	}

	fmt.Println("Connected to PostgreSQL!")

	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PATCH", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "sessionKey"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	router.POST("/register", register)
	router.POST("/login", login)
	router.POST("/api/todokanban", kanban)
	router.GET("/api/todos", getTodos)
	router.POST("/api/todos", createTodo)
	router.PATCH("/api/todos/:id", updateTodo)
	router.DELETE("/api/todos/:id", deleteTodo)
	router.PATCH("/api/todos/:id/status", updateTodoStatus)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	router.Run(":" + port)
}

// Register a new user
func register(c *gin.Context) {
	var user User

	// Bind JSON input
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server error while hashing password"})
		return
	}

	// Insert user into the database
	_, err = db.Exec("INSERT INTO users (id, username, password, email) VALUES (uuid_generate_v4(), $1, $2, $3)", user.Username, hashedPassword, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

// User login
func login(c *gin.Context) {
	var user User

	// Parse JSON input
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var storedPassword string
	var userID int

	// Fetch password and user ID from DB
	err := db.QueryRow("SELECT id, password FROM users WHERE username=$1", user.Username).Scan(&userID, &storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query database"})
		return
	}

	// Compare the hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "user_id": userID})
}

// Get all todos for the logged-in user
func getTodos(c *gin.Context) {
	// Get the session key from the headers
	sessionKey := c.GetHeader("sessionKey")
	if sessionKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing session key"})
		return
	}

	// Retrieve userID from Redis
	userID, err := Rdb.Get(ctx, sessionKey).Result()
	if err == redis.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session key"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate session key"})
		return
	}

	// Execute the query using the userID retrieved from Redis
	rows, err := db.Query("SELECT id, completed, body FROM todos WHERE user_id = $1", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var todos []Todo
	for rows.Next() {
		var todo Todo
		if err := rows.Scan(&todo.ID, &todo.Completed, &todo.Body); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		todos = append(todos, todo)
	}

	c.JSON(http.StatusOK, todos)
}

func createTodo(c *gin.Context) {
	var todo Todo
	if err := c.ShouldBindJSON(&todo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	sessionKey := c.GetHeader("sessionKey")
	if sessionKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing session key"})
		return
	}

	// Retrieve userID from Redis
	userID, err := Rdb.Get(ctx, sessionKey).Result()
	if err == redis.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session key"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate session key"})
		return
	}

	// Log the userID for debugging
	fmt.Println("Retrieved userID from Redis:", userID)

	// Convert userID to UUID
	var userIDUUID uuid.UUID
	err = userIDUUID.UnmarshalText([]byte(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to convert user ID"})
		return
	}

	// Set the userID field in the Todo struct
	todo.UserID = userIDUUID.String() // Store userID as a string for logging, but ensure you're inserting the UUID

	// Log the todo for debugging
	fmt.Println("Creating todo with UserID:", todo.UserID)

	// Insert the todo into the database
	err = db.QueryRow("INSERT INTO todos (user_id, completed, body) VALUES ($1, $2, $3) RETURNING id", userIDUUID, todo.Completed, todo.Body).Scan(&todo.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, todo)
}

// Update an existing todo
func updateTodo(c *gin.Context) {
	id := c.Param("id")
	var todo Todo
	if err := c.ShouldBindJSON(&todo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	_, err := db.Exec("UPDATE todos SET completed = $1 WHERE id = $2", todo.Completed, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// Delete a todo
func deleteTodo(c *gin.Context) {
	id := c.Param("id")

	_, err := db.Exec("DELETE FROM todos WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// Kanban endpoint: Get todos grouped by status
func kanban(c *gin.Context) {
	sessionKey := c.GetHeader("sessionKey")
	if sessionKey == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing session key"})
		return
	}

	// Retrieve userID from Redis
	userID, err := Rdb.Get(ctx, sessionKey).Result()
	if err == redis.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session key"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate session key"})
		return
	}

	// Fetch todos grouped by status
	query := `SELECT id, completed, body, status FROM todos WHERE user_id = $1 ORDER BY status`
	rows, err := db.Query(query, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var todos []Todo
	for rows.Next() {
		var todo Todo
		if err := rows.Scan(&todo.ID, &todo.Completed, &todo.Body, &todo.Status); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		todos = append(todos, todo)
	}

	c.JSON(http.StatusOK, todos)
}

// Update the status of a todo for kanban
func updateTodoStatus(c *gin.Context) {
	id := c.Param("id")
	var todo Todo
	if err := c.ShouldBindJSON(&todo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Update the todo's status
	_, err := db.Exec("UPDATE todos SET status = $1 WHERE id = $2", todo.Status, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}
