package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Hardcoded user data based on realm-export.json
var userData = map[string][]string{
	"user1":      {"User", "One", "250ms", "10"},
	"user2":      {"User", "Two", "300ms", "8"},
	"admin1":     {"Admin", "One", "200ms", "12"},
	"prothetic1": {"Prothetic", "One", "180ms", "15"},
	"prothetic2": {"Prothetic", "Two", "220ms", "11"},
	"prothetic3": {"Prothetic", "Three", "210ms", "9"},
}

// Keycloak configuration
const (
	keycloakURL = "http://keycloak:8080"
	realm       = "reports-realm"
)

var keySet jwk.Set

// CORS middleware
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next(w, r)
	}
}

func main() {
	// Load Keycloak's public keys on startup
	if err := loadKeycloakKeys(); err != nil {
		log.Fatal("Failed to load Keycloak keys:", err)
	}

	http.HandleFunc("/reports", corsMiddleware(reportsHandler))
	fmt.Println("Server started at :8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func loadKeycloakKeys() error {
	// Fetch Keycloak's JWKS (JSON Web Key Set)
	ctx := context.Background()
	keySetURL := "http://keycloak:8080/realms/reports-realm/protocol/openid-connect/certs"

	keys, err := jwk.Fetch(ctx, keySetURL)
	if err != nil {
		return fmt.Errorf("failed to fetch Keycloak keys: %v", err)
	}

	keySet = keys
	fmt.Println("Successfully loaded Keycloak public keys")
	return nil
}

func reportsHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := extractBearerToken(r.Header.Get("Authorization"))
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Missing or invalid Authorization header"))
		return
	}

	username, err := validateAndGetUsername(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid token: " + err.Error()))
		return
	}

	data, ok := userData[username]
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("User not found"))
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=report.csv")
	csvWriter := csv.NewWriter(w)
	csvWriter.Write([]string{"name", "surname", "average reaction time", "total hours of usage"})
	csvWriter.Write(data)
	csvWriter.Flush()
}

func extractBearerToken(header string) string {
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	return ""
}

func validateAndGetUsername(tokenString string) (string, error) {
	// Parse and validate the JWT token
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(5*time.Second),
	)
	if err != nil {
		return "", fmt.Errorf("failed to validate token: %v", err)
	}

	// Extract username
	username, ok := token.Get("preferred_username")
	if !ok {
		return "", fmt.Errorf("preferred_username not found in token")
	}

	usernameStr, ok := username.(string)
	if !ok {
		return "", fmt.Errorf("preferred_username is not a string")
	}

	// Check realm access roles
	realmAccess, ok := token.Get("realm_access")
	if !ok {
		return "", fmt.Errorf("realm_access not found in token")
	}

	realmAccessMap, ok := realmAccess.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("realm_access is not a map")
	}

	roles, ok := realmAccessMap["roles"].([]interface{})
	if !ok {
		return "", fmt.Errorf("roles not found in token")
	}

	// Check if user has prothetic_user role
	hasProtheticRole := false
	for _, role := range roles {
		if roleStr, ok := role.(string); ok && roleStr == "prothetic_user" {
			hasProtheticRole = true
			break
		}
	}

	if !hasProtheticRole {
		return "", fmt.Errorf("user does not have prothetic_user role")
	}

	return usernameStr, nil
}
