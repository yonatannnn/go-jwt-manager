package main

import (
	"fmt"
	"log"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/yonatannnn/go-jwt-manager/auth"
)

func main() {
	// Initialize JWT manager
	jwtManager := auth.NewJWTManager("your-secret-key-here")

	// Create Gin router
	router := gin.Default()

	// Public routes
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to the API",
			"endpoints": []string{
				"POST /login - Login to get token",
				"GET /profile - Get user profile (requires auth)",
				"GET /admin - Admin panel (requires admin role)",
				"GET /moderator - Moderator panel (requires moderator role)",
				"GET /sensitive-data - Sensitive data (requires permission)",
				"GET /user/:id - User data (ABAC)",
			},
		})
	})

	// Login endpoint
	router.POST("/login", func(c *gin.Context) {
		var loginReq struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&loginReq); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		// Simulate user authentication
		var token string
		var err error

		switch loginReq.Email {
		case "admin@example.com":
			// Admin user
			token, err = jwtManager.GenerateForUser("admin-123", loginReq.Email, []string{"admin", "user"}, 1*time.Hour)
		case "moderator@example.com":
			// Moderator user
			token, err = jwtManager.GenerateForUser("moderator-456", loginReq.Email, []string{"moderator", "user"}, 1*time.Hour)
		case "user@example.com":
			// Regular user
			token, err = jwtManager.GenerateForUser("user-789", loginReq.Email, []string{"user"}, 1*time.Hour)
		case "service@example.com":
			// Service account
			token, err = jwtManager.GenerateForService("service-123", []string{"read:sensitive", "write:data"}, 24*time.Hour)
		default:
			c.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(200, gin.H{
			"token": token,
			"type":  "Bearer",
		})
	})

	// Protected routes
	router.GET("/profile", auth.GinAuthMiddleware(jwtManager), func(c *gin.Context) {
		claims, _ := auth.GetGinClaims(c)
		c.JSON(200, gin.H{
			"message": "Profile accessed successfully",
			"user_id": claims["user_id"],
			"email":   claims["email"],
			"roles":   claims["roles"],
		})
	})

	// Admin-only route
	router.GET("/admin", auth.GinAuthMiddleware(jwtManager), auth.GinRequireRole("admin"), func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Admin panel accessed successfully",
			"features": []string{
				"User management",
				"System settings",
				"Analytics dashboard",
			},
		})
	})

	// Moderator route with manual role checking
	router.GET("/moderator", auth.GinAuthMiddleware(jwtManager), func(c *gin.Context) {
		claims, _ := auth.GetGinClaims(c)
		roles := claims["roles"].([]string)

		hasModeratorRole := false
		for _, role := range roles {
			if role == "admin" || role == "moderator" {
				hasModeratorRole = true
				break
			}
		}

		if !hasModeratorRole {
			c.JSON(403, gin.H{"error": "Insufficient permissions. Moderator or admin role required."})
			return
		}

		c.JSON(200, gin.H{
			"message": "Moderator panel accessed successfully",
			"features": []string{
				"Content moderation",
				"User reports",
				"Community guidelines",
			},
		})
	})

	// Permission-based access
	router.GET("/sensitive-data", auth.GinAuthMiddleware(jwtManager), auth.GinRequirePermission("read:sensitive"), func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Sensitive data accessed successfully",
			"data": map[string]interface{}{
				"financial_records": "***",
				"personal_info":     "***",
				"security_logs":     "***",
			},
		})
	})

	// ABAC example - users can only access their own data or if they're admin
	router.GET("/user/:id", auth.GinAuthMiddleware(jwtManager), auth.GinRequireABAC(func(claims map[string]interface{}) bool {
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
		requestedUserID := c.Param("id")
		claims, _ := auth.GetGinClaims(c)
		userID := claims["user_id"].(string)

		c.JSON(200, gin.H{
			"message":            "User data accessed successfully",
			"requested_user_id":  requestedUserID,
			"authenticated_user": userID,
			"user_data": map[string]interface{}{
				"id":       requestedUserID,
				"email":    "user@example.com",
				"profile":  "***",
				"settings": "***",
			},
		})
	})

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	// Start server
	fmt.Println("🚀 Gin server starting on :8080...")
	fmt.Println("📝 Available endpoints:")
	fmt.Println("  POST /login - Login to get token")
	fmt.Println("  GET /profile - Get user profile (requires auth)")
	fmt.Println("  GET /admin - Admin panel (requires admin role)")
	fmt.Println("  GET /moderator - Moderator panel (requires moderator role)")
	fmt.Println("  GET /sensitive-data - Sensitive data (requires permission)")
	fmt.Println("  GET /user/:id - User data (ABAC)")
	fmt.Println("  GET /health - Health check")
	fmt.Println("\n🔑 Test users:")
	fmt.Println("  admin@example.com - Admin user")
	fmt.Println("  moderator@example.com - Moderator user")
	fmt.Println("  user@example.com - Regular user")
	fmt.Println("  service@example.com - Service account")

	if err := router.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
