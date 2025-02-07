package main

// UserClaims represents the JWT claims structure
type UserClaims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Sub   string `json:"sub"`
}

// APIResponse represents the response structure for API endpoints
type APIResponse struct {
	Message string `json:"message"`
	User    User   `json:"user,omitempty"`
	Error   string `json:"error,omitempty"`
}

// User represents the user data structure
type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}
