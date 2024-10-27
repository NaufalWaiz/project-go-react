package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	// "github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db  *sql.DB
	Rdb *redis.Client
	ctx = context.Background()
)

func main() {
	// Redis connection
	Rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer Rdb.Close()

	// Test the Redis connection with Ping
	if _, err := Rdb.Ping(ctx).Result(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	} else {
		log.Println("Successfully connected to Redis!")
	}

	// Connection to PostgreSQL database
	connStr := "user=postgres password=mysecretpassword dbname=postgres sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	// Check if the database connection is working
	if err = db.Ping(); err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	router := gin.Default()

	// Middleware CORS
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"}, // Frontend React URL
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "sessionKey", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Register and login routes
	router.POST("/register", register)
	router.POST("/login", login)

	// Protected route example (optional)
	// router.GET("/protected", sessionValidationMiddleware, protectedRoute)

	fmt.Println("Server started at :8081")
	router.Run(":8081")
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// Middleware to validate session key
func sessionValidationMiddleware(c *gin.Context) {
	sessionKey := c.GetHeader("sessionKey")

	if sessionKey == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing session key"})
		return
	}

	// Check if the session key exists in Redis
	userID, err := Rdb.Get(ctx, sessionKey).Result()
	if err == redis.Nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session key"})
		return
	} else if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate session key"})
		return
	}

	// Pass user ID to the next handler
	c.Set("userID", userID)
	c.Next()
}

func register(c *gin.Context) {
	var user User

	// Bind JSON input
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server error while hashing password"})
		return
	}

	// Insert into the users table (without specifying the id, it will be auto-generated)
	_, err = db.Exec("INSERT INTO users (username, password, email) VALUES ($1, $2, $3)", user.Username, hashedPassword, user.Email)
	if err != nil {
		if err.Error() == "pq: duplicate key value violates unique constraint \"users_username_key\"" {
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
			return
		} else if err.Error() == "pq: duplicate key value violates unique constraint \"users_email_key\"" {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func login(c *gin.Context) {
	var user User

	// Parse JSON input
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var storedPassword string
	var userID string

	// Fetch password and user_id from DB (referencing the users table now)
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

	// Generate a session key
	sessionKey := fmt.Sprintf("%s:%s:%d", user.Username, userID, time.Now().UnixNano())

	// Store session key in Redis with 30-minute expiry
	err = Rdb.Set(ctx, sessionKey, userID, 30*time.Minute).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": "Failed to create session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":       user.Username,
		"sessionKey": sessionKey,
		"message":    "Login successful",
	})
}

// ME Function
// func Me(db *sqlx.DB) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		// Get the session key from the request headers
// 		sessionKey := c.Request.Header.Get("Session-Key")

// 		if sessionKey == "" {
// 			c.JSON(http.StatusUnauthorized, gin.H{"msg": "Try to login"})
// 			return
// 		}

// 		email, err := Rdb.Get(ctx, sessionKey).Result()
// 		if err != nil {
// 			c.JSON(http.StatusUnauthorized, gin.H{"msg": "Try to login"})
// 			return
// 		}

// 		var user User
// 		var userID, storedPassword string
// 		err = db.QueryRow("SELECT id, password FROM users WHERE username=$1", user.Username).Scan(&userID, &storedPassword)
// 		if err != nil {
// 			if err == sql.ErrNoRows {
// 				c.JSON(http.StatusNotFound, gin.H{"msg": "User not found"})
// 			} else {
// 				c.JSON(http.StatusInternalServerError, gin.H{"msg": "Internal Server Error"})
// 			}
// 			return
// 		}

// 		c.JSON(http.StatusOK, user)
// 	}
// }