package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yonatannnn/go-jwt-manager/auth"
)

func main() {
	// 1. Basic Setup
	jwtManager := auth.NewJWTManager("your-secret-key-here")

	// 2. Token Generation Examples
	exampleTokenGeneration(jwtManager)

	// 3. Web Framework Examples
	exampleGinFramework(jwtManager)
	exampleStandardHTTP(jwtManager)
}

func exampleTokenGeneration(jwtManager *auth.JWTManager) {
	fmt.Println("=== Token Generation Examples ===")

	// A. Default expiration (15 minutes)
	token, err := jwtManager.Generate(map[string]interface{}{
		"user_id": "123",
		"email":   "user@example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Default token: %s\n", token[:50]+"...")

	// B. Custom expiration (24 hours)
	token, err = jwtManager.Generate(map[string]interface{}{
		"user_id": "456",
		"email":   "admin@example.com",
		"roles":   []string{"admin", "user"},
	}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("24h token: %s\n", token[:50]+"...")

	// C. Never-expiring token
	token, err = jwtManager.Generate(map[string]interface{}{
		"app_id": "service-account-789",
		"type":   "microservice",
	}, 0) // 0 duration = no expiration
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("No-expiry token: %s\n", token[:50]+"...")

	// D. With custom claims
	token, err = jwtManager.Generate(map[string]interface{}{
		"sub": "user-123",
		"aud": "mobile-app",
		"iss": "your-api",
		"custom_data": map[string]interface{}{
			"plan":       "premium",
			"trial_ends": "2023-12-31",
		},
	}, 8*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Custom claims token: %s\n", token[:50]+"...")

	// E. Using convenience methods
	userToken, err := jwtManager.GenerateForUser("user-123", "user@example.com", []string{"user"}, 1*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User token: %s\n", userToken[:50]+"...")

	serviceToken, err := jwtManager.GenerateForService("service-456", []string{"read", "write"}, 24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Service token: %s\n", serviceToken[:50]+"...")

	// Verify a token
	claims, err := jwtManager.Verify(userToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Verified claims: %+v\n", claims)
}

func exampleGinFramework(jwtManager *auth.JWTManager) {
	fmt.Println("\n=== Gin Framework Examples ===")

	router := gin.Default()

	// Public routes
	router.GET("/public", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Public endpoint"})
	})

	// Protected route requiring any valid token
	router.GET("/profile", auth.GinAuthMiddleware(jwtManager), func(c *gin.Context) {
		claims, _ := auth.GetGinClaims(c)
		c.JSON(200, gin.H{
			"message": "Profile accessed",
			"user_id": claims["user_id"],
		})
	})

	// Admin-only route
	router.GET("/admin", auth.GinAuthMiddleware(jwtManager), auth.GinRequireRole("admin"), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Admin panel accessed"})
	})

	// Multiple role requirement
	router.GET("/moderator", auth.GinAuthMiddleware(jwtManager), func(c *gin.Context) {
		claims, _ := auth.GetGinClaims(c)
		roles := claims["roles"].([]string)

		if !contains(roles, "admin") && !contains(roles, "moderator") {
			c.JSON(403, gin.H{"error": "Insufficient permissions"})
			return
		}

		c.JSON(200, gin.H{"message": "Moderator panel accessed"})
	})

	// Permission-based access
	router.GET("/sensitive-data", auth.GinAuthMiddleware(jwtManager), auth.GinRequirePermission("read:sensitive"), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Sensitive data accessed"})
	})

	// ABAC example
	router.GET("/user/:id", auth.GinAuthMiddleware(jwtManager), auth.GinRequireABAC(func(claims map[string]interface{}) bool {
		// User can only access their own data or if they're admin
		userID := claims["user_id"].(string)
		roles := claims["roles"].([]string)

		// Admin can access any user data
		for _, role := range roles {
			if role == "admin" {
				return true
			}
		}

		// Regular users can only access their own data
		return userID == claims["user_id"].(string)
	}), func(c *gin.Context) {
		userID := c.Param("id")
		c.JSON(200, gin.H{"message": "User data accessed", "user_id": userID})
	})

	fmt.Println("Gin server starting on :8080...")
	router.Run(":8080")
}

func exampleStandardHTTP(jwtManager *auth.JWTManager) {
	fmt.Println("\n=== Standard HTTP Examples ===")

	mux := http.NewServeMux()

	// Public handler
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Public endpoint"))
	})

	// Protected API handler
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := auth.GetUserClaims(r)
		w.Write([]byte(fmt.Sprintf("API accessed by user: %v", claims["user_id"])))
	})

	// Admin handler
	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Admin panel accessed"))
	})

	// Apply middleware
	mux.Handle("/api", auth.AuthMiddleware(jwtManager)(apiHandler))
	mux.Handle("/admin", auth.AuthMiddleware(jwtManager)(auth.RequireRole("admin")(adminHandler)))

	fmt.Println("Standard HTTP server starting on :8081...")
	http.ListenAndServe(":8081", mux)
}

// Helper function to check if slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
