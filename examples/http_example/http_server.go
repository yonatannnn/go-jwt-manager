package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/yonatannnn/go-jwt-manager/auth"
)

func main() {
	// Initialize JWT manager
	jwtManager := auth.NewJWTManager("your-secret-key-here")

	// Create HTTP mux
	mux := http.NewServeMux()

	// Public handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"message": "Welcome to the API",
			"endpoints": []string{
				"POST /login - Login to get token",
				"GET /api - Protected API (requires auth)",
				"GET /admin - Admin panel (requires admin role)",
			},
		}
		writeJSON(w, response)
	})

	// Login handler
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var loginReq struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Simulate user authentication
		var token string
		var err error

		switch loginReq.Email {
		case "admin@example.com":
			// Admin user
			token, err = jwtManager.GenerateForUser("admin-123", loginReq.Email, []string{"admin", "user"}, 1*time.Hour)
		case "user@example.com":
			// Regular user
			token, err = jwtManager.GenerateForUser("user-789", loginReq.Email, []string{"user"}, 1*time.Hour)
		default:
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"token": token,
			"type":  "Bearer",
		}
		writeJSON(w, response)
	})

	// Protected API handler
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := auth.GetUserClaims(r)
		if err != nil {
			http.Error(w, "Failed to get claims", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"message": "API accessed successfully",
			"user_id": claims["user_id"],
			"email":   claims["email"],
			"roles":   claims["roles"],
		}
		writeJSON(w, response)
	})

	// Admin handler
	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"message": "Admin panel accessed successfully",
			"features": []string{
				"User management",
				"System settings",
				"Analytics dashboard",
			},
		}
		writeJSON(w, response)
	})

	// Apply middleware
	mux.Handle("/api", auth.AuthMiddleware(jwtManager)(apiHandler))
	mux.Handle("/admin", auth.AuthMiddleware(jwtManager)(auth.RequireRole("admin")(adminHandler)))

	// Health check handler
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		}
		writeJSON(w, response)
	})

	// Start server
	fmt.Println("🚀 HTTP server starting on :8081...")
	fmt.Println("📝 Available endpoints:")
	fmt.Println("  POST /login - Login to get token")
	fmt.Println("  GET /api - Protected API (requires auth)")
	fmt.Println("  GET /admin - Admin panel (requires admin role)")
	fmt.Println("  GET /health - Health check")
	fmt.Println("\n🔑 Test users:")
	fmt.Println("  admin@example.com - Admin user")
	fmt.Println("  user@example.com - Regular user")

	if err := http.ListenAndServe(":8081", mux); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Helper function to write JSON responses
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
