# 🚀 Go JWT Manager

A simple, powerful, and easy-to-use JWT authentication package for Go applications. Perfect for both user authentication and service-to-service communication.

## 📦 Installation

```bash
go get github.com/yonatannnn/go-jwt-manager
```

## 🎯 Quick Start

### 1. Basic Setup

```go
import "github.com/yonatannnn/go-jwt-manager/auth"

// Initialize with default 15-minute token expiration
jwtManager := auth.NewJWTManager("your-secret-key-here")

// Or with custom duration
jwtManager := auth.NewJWTManagerWithDuration("your-secret-key-here", 24*time.Hour)
```

### 2. Token Generation

#### A. Default expiration (15 minutes):
```go
token, err := jwtManager.Generate(map[string]interface{}{
    "user_id": "123",
    "email":   "user@example.com",
})
```

#### B. Custom expiration (24 hours):
```go
token, err := jwtManager.Generate(map[string]interface{}{
    "user_id": "456",
    "email":   "admin@example.com",
    "roles":   []string{"admin", "user"},
}, 24*time.Hour)
```

#### C. Never-expiring token:
```go
token, err := jwtManager.Generate(map[string]interface{}{
    "app_id": "service-account-789",
    "type":   "microservice",
}, 0) // 0 duration = no expiration
```

#### D. With custom claims:
```go
token, err := jwtManager.Generate(map[string]interface{}{
    "sub": "user-123",
    "aud": "mobile-app",
    "iss": "your-api",
    "custom_data": map[string]interface{}{
        "plan":       "premium",
        "trial_ends": "2023-12-31",
    },
}, 8*time.Hour)
```

### 3. Convenience Methods

#### For User Authentication:
```go
token, err := jwtManager.GenerateForUser("user-123", "user@example.com", []string{"user"}, 1*time.Hour)
```

#### For Service-to-Service Authentication:
```go
token, err := jwtManager.GenerateForService("service-456", []string{"read", "write"}, 24*time.Hour)
```

### 4. Token Verification & Data Extraction

```go
claims, err := jwtManager.Verify(token)
if err != nil {
    // Handle error
}

// Easy data extraction with helper methods
userID, err := auth.GetUserID(claims)
email, err := auth.GetEmail(claims)
roles, err := auth.GetRoles(claims)

// Or use safe extraction with defaults
userID := auth.ExtractStringOrDefault(claims, "user_id", "unknown")
isAdmin := auth.HasRole(claims, "admin")
canRead := auth.HasPermission(claims, "read:sensitive")
```

### 5. Data Extraction Helper Methods

The package provides many helper methods to safely extract data from JWT claims:

#### Basic Extraction Methods:
```go
// String extraction
userID, err := auth.ExtractString(claims, "user_id")
userID := auth.ExtractStringOrDefault(claims, "user_id", "unknown")

// Number extraction
age, err := auth.ExtractInt(claims, "age")
age := auth.ExtractIntOrDefault(claims, "age", 0)

// Boolean extraction
isActive, err := auth.ExtractBool(claims, "is_active")
isActive := auth.ExtractBoolOrDefault(claims, "is_active", false)

// Slice extraction
roles, err := auth.ExtractStringSlice(claims, "roles")
roles := auth.ExtractStringSliceOrDefault(claims, "roles", []string{"user"})

// Map extraction
customData, err := auth.ExtractMap(claims, "custom_data")
customData := auth.ExtractMapOrDefault(claims, "custom_data", map[string]interface{}{})
```

#### Common JWT Claims:
```go
// Standard JWT claims
userID, err := auth.GetUserID(claims)
email, err := auth.GetEmail(claims)
roles, err := auth.GetRoles(claims)
permissions, err := auth.GetPermissions(claims)
subject, err := auth.GetSubject(claims)
issuer, err := auth.GetIssuer(claims)
audience, err := auth.GetAudience(claims)
```

#### Role & Permission Checks:
```go
// Check if user has specific role
if auth.HasRole(claims, "admin") {
    // Admin functionality
}

// Check if user has specific permission
if auth.HasPermission(claims, "read:sensitive") {
    // Access sensitive data
}
```

### 6. Utility Methods

```go
// Check if token is expired
expired, err := jwtManager.IsExpired(token)

// Get expiration time
expTime, err := jwtManager.GetExpirationTime(token)
```

## 🌐 Web Framework Integration

### Gin Framework

```go
router := gin.Default()

// Protected route requiring any valid token
router.GET("/profile", auth.GinAuthMiddleware(jwtManager), func(c *gin.Context) {
    claims, _ := auth.GetGinClaims(c)
    
    // Easy data extraction
    userID, _ := auth.GetUserID(claims)
    email, _ := auth.GetEmail(claims)
    roles, _ := auth.GetRoles(claims)
    
    c.JSON(200, gin.H{
        "message": "Profile accessed",
        "user_id": userID,
        "email":   email,
        "roles":   roles,
    })
})

// Admin-only route
router.GET("/admin", auth.GinAuthMiddleware(jwtManager), auth.GinRequireRole("admin"), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "Admin panel accessed"})
})

// Multiple role requirement
router.GET("/moderator", auth.GinAuthMiddleware(jwtManager), func(c *gin.Context) {
    claims, _ := auth.GetGinClaims(c)
    
    if !auth.HasRole(claims, "admin") && !auth.HasRole(claims, "moderator") {
        c.JSON(403, gin.H{"error": "Insufficient permissions"})
        return
    }
    
    c.JSON(200, gin.H{"message": "Moderator panel accessed"})
})

// Permission-based access
router.GET("/sensitive-data", auth.GinAuthMiddleware(jwtManager), auth.GinRequirePermission("read:sensitive"), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "Sensitive data accessed"})
})

// ABAC (Attribute-Based Access Control)
router.GET("/user/:id", auth.GinAuthMiddleware(jwtManager), auth.GinRequireABAC(func(claims map[string]interface{}) bool {
    // User can only access their own data or if they're admin
    userID, _ := auth.GetUserID(claims)
    return auth.HasRole(claims, "admin") || userID == claims["user_id"].(string)
}), func(c *gin.Context) {
    userID := c.Param("id")
    c.JSON(200, gin.H{"message": "User data accessed", "user_id": userID})
})
```

### Standard net/http

```go
mux := http.NewServeMux()

// Public handler
mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Public endpoint"))
})

// Protected API handler
apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claims, _ := auth.GetUserClaims(r)
    
    // Easy data extraction
    userID, _ := auth.GetUserID(claims)
    email, _ := auth.GetEmail(claims)
    
    w.Write([]byte(fmt.Sprintf("API accessed by user: %s (%s)", userID, email)))
})

// Admin handler
adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Admin panel accessed"))
})

// Apply middleware
mux.Handle("/api", auth.AuthMiddleware(jwtManager)(apiHandler))
mux.Handle("/admin", auth.AuthMiddleware(jwtManager)(auth.RequireRole("admin")(adminHandler)))
```

## 🔐 Middleware Types

### Authentication Middleware
- `AuthMiddleware(jwtManager)` - Standard HTTP middleware
- `GinAuthMiddleware(jwtManager)` - Gin framework middleware

### Role-Based Access Control (RBAC)
- `RequireRole("admin", "moderator")` - Standard HTTP
- `GinRequireRole("admin", "moderator")` - Gin framework

### Permission-Based Access Control
- `RequirePermission("read:sensitive")` - Standard HTTP
- `GinRequirePermission("read:sensitive")` - Gin framework

### Attribute-Based Access Control (ABAC)
- `RequireABAC(ruleFunc)` - Standard HTTP
- `GinRequireABAC(ruleFunc)` - Gin framework

## 🔄 Refresh Token Support

```go
refreshManager := auth.NewRefreshManager("refresh-secret-key", 7*24*time.Hour)

// Generate refresh token
refreshToken, err := refreshManager.Generate(map[string]interface{}{
    "user_id": "123",
    "session_id": "session-456",
})

// Verify refresh token
claims, err := refreshManager.Verify(refreshToken)
```

## 🛡️ Security Features

- **HS256 Signing**: Uses HMAC-SHA256 for token signing
- **Automatic Expiration**: Built-in token expiration handling
- **Flexible Claims**: Support for custom claims and standard JWT claims
- **Role-Based Access**: Multiple role support with flexible checking
- **Permission-Based Access**: Fine-grained permission control
- **ABAC Support**: Attribute-based access control for complex scenarios
- **Refresh Tokens**: Separate refresh token management
- **Error Handling**: Comprehensive error handling and validation
- **Safe Data Extraction**: Type-safe helper methods for extracting claims

## 📋 Token Structure

The package automatically adds standard JWT claims:

```json
{
  "user_id": "123",
  "email": "user@example.com",
  "roles": ["user", "admin"],
  "iat": 1640995200,
  "exp": 1640996100
}
```

## 🚀 Advanced Usage

### Custom Token Duration
```go
// 15 minutes (default)
token, err := jwtManager.Generate(claims)

// 24 hours
token, err := jwtManager.Generate(claims, 24*time.Hour)

// No expiration
token, err := jwtManager.Generate(claims, 0)
```

### Service-to-Service Authentication
```go
token, err := jwtManager.GenerateForService("service-123", []string{"read", "write"}, 24*time.Hour)
```

### Complex ABAC Rules
```go
router.GET("/data/:id", auth.GinAuthMiddleware(jwtManager), auth.GinRequireABAC(func(claims map[string]interface{}) bool {
    userID, _ := auth.GetUserID(claims)
    roles, _ := auth.GetRoles(claims)
    permissions, _ := auth.GetPermissions(claims)
    
    // Admin can access everything
    if auth.HasRole(claims, "admin") {
        return true
    }
    
    // Users with specific permission can access
    if auth.HasPermission(claims, "data:read") {
        return true
    }
    
    // Users can access their own data
    return userID == claims["user_id"].(string)
}), handler)
```

## 🔧 Configuration

### Environment Variables
```bash
export JWT_SECRET_KEY="your-super-secret-key-here"
export JWT_TOKEN_DURATION="15m"
export JWT_REFRESH_DURATION="168h"  # 7 days
```

### Custom Configuration
```go
jwtManager := auth.NewJWTManagerWithDuration(
    os.Getenv("JWT_SECRET_KEY"),
    parseDuration(os.Getenv("JWT_TOKEN_DURATION")),
)
```

## 📚 Examples

See the `examples/` directory for complete working examples:

- `examples/basic_example/` - Comprehensive usage examples
- `examples/gin_example/` - Complete Gin server with JWT auth
- `examples/http_example/` - Standard HTTP server with JWT auth

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you have any questions or need help, please open an issue on GitHub.

---

**Made with ❤️ for the Go community** 