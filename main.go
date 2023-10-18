package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	identity "example.com/demo2/IdentityProvider"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

type OAuthConfig interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(token *oauth2.Token) (string, error)
}

type IdentityProvider struct {
	Name string
	OAuthConfig
}

const (
	// Hardcoded secret key
	secretKey = "your_secret_key_here"
)

func (i *IdentityProvider) VerifyToken(tokenString string) (bool, error) {
	// Example JWT verification logic using the JWT library
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		return false, fmt.Errorf("token verification failed: %v", err)
	}

	// Validate the token's expiration time
	if !parsedToken.Valid {
		return false, fmt.Errorf("token is invalid")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("invalid token claims")
	}

	// Verify the token's expiration time and issuance time
	now := time.Now()
	expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
	issuedAt := time.Unix(int64(claims["iat"].(float64)), 0)

	if now.After(expirationTime) || now.Before(issuedAt) {
		return false, fmt.Errorf("token is expired or not yet valid")
	}

	return true, nil
}

type CustomOAuthConfig struct {
	*oauth2.Config
}

func (c *CustomOAuthConfig) GetUserInfo(token *oauth2.Token) (string, error) {
	return "User Info", nil // Replace with your implementation
}

type OAuthConfigAdapter struct {
	config *CustomOAuthConfig
}

func (oa *OAuthConfigAdapter) AuthCodeURL(state string) string {
	return oa.config.AuthCodeURL(state)
}

func (oa *OAuthConfigAdapter) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return oa.config.Exchange(ctx, code)
}

func (oa *OAuthConfigAdapter) GetUserInfo(token *oauth2.Token) (string, error) {
	return oa.config.GetUserInfo(token)
}

//functions

func handleLogin(w http.ResponseWriter, r *http.Request, identityProvider *IdentityProvider) {
	url := identityProvider.AuthCodeURL("random")
	http.Redirect(w, r, url, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request, identityProvider *IdentityProvider) {
	// handling the callback in the same way
	//we can redirect user from here to Jaeger UI
	// ...
}

func handleHome(w http.ResponseWriter, r *http.Request, identityProviders []*IdentityProvider) {
	fmt.Fprintf(w, "<html><head><title>Jaeger Authentication Home Page</title></head><body style=\"background-color: #f2f2f2; text-align: center; padding-top: 50px;\">")
	fmt.Fprintf(w, "<h1 style=\"color: #0f4c81;\">Welcome to the Jaeger Authentication Home Page</h1>")
	fmt.Fprintf(w, "<img src='/static/Jaeger.png' alt='Jaeger' style='width: 200px; height: 200px; margin-top: 20px;'>") // Adjust the image width, height, and margin as needed
	fmt.Fprintf(w, "<p style=\"font-size: 18px;\">Choose an identity provider to get started:</p>")
	fmt.Fprintf(w, "<div style=\"display: flex; justify-content: center; align-items: center; margin-top: 30px;\">")

	for _, provider := range identityProviders {
		fmt.Fprintf(w, "<div style=\"margin: 20px;\">") // Adjust the margin value as needed
		fmt.Fprintf(w, "<a href='/login/%s'><img src='%s' alt='%s' style='width: 150px; height: 150px; border-radius: 50%;'></a>", provider.Name, getProviderImage(provider.Name), provider.Name)
		fmt.Fprintf(w, "<p style='margin-top: 10px; color: #0f4c81;'><a href='/login/%s'>Authenticate with %s</a></p>", provider.Name, provider.Name)
		fmt.Fprintf(w, "</div>")
	}

	fmt.Fprintf(w, "</div></body></html>")
}

// getting images from static fileServer
func getProviderImage(providerName string) string {
	switch providerName {
	case "Google":
		return "/static/google.png"
	case "IDP1":
		return "/static/github.png"
	case "IDP2":
		return "/static/microsoft.png"
	default:
		return "https://via.placeholder.com/150" // Default
	}
}

func handleVerification(w http.ResponseWriter, r *http.Request, provider *IdentityProvider) {
	// Your JWT verification endpoint logic here
	// Extract the token from the request and verify it using the identity provider
	// Respond with the verification result
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Authorization token missing", http.StatusUnauthorized)
		return
	}

	valid, err := provider.VerifyToken(tokenString)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := struct {
		Valid bool `json:"valid"`
	}{
		Valid: valid,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

//setting up routes

func setupRoutes(provider *IdentityProvider) {
	http.HandleFunc(fmt.Sprintf("/login/%s", provider.Name), func(w http.ResponseWriter, r *http.Request) {
		handleLogin(w, r, provider)
	})

	http.HandleFunc(fmt.Sprintf("/callback/%s", provider.Name), func(w http.ResponseWriter, r *http.Request) {
		handleCallback(w, r, provider)
	})

	http.HandleFunc(fmt.Sprintf("/verify/%s", provider.Name), func(w http.ResponseWriter, r *http.Request) {
		handleVerification(w, r, provider)
	})
}

// LoadIdentityProviders loads the identity provider details from the specified YAML file
func LoadIdentityProviders(filepath string) ([]*IdentityProvider, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config identity.IdentityProviderConfig
	err = yaml.NewDecoder(file).Decode(&config)
	if err != nil {
		return nil, err
	}

	var identityProviders []*IdentityProvider
	for _, provider := range config.IdentityProviders {
		identityProviders = append(identityProviders, &IdentityProvider{
			Name: provider.Name,
			OAuthConfig: &OAuthConfigAdapter{
				config: &CustomOAuthConfig{
					Config: &oauth2.Config{
						ClientID:     provider.ClientID,
						ClientSecret: provider.ClientSecret,
						RedirectURL:  provider.RedirectURL,
						Scopes:       provider.Scopes,
						Endpoint: oauth2.Endpoint{
							AuthURL:  provider.AuthURL,
							TokenURL: provider.TokenURL,
						},
					},
				},
			},
		})
	}
	return identityProviders, nil
}

func main() {

	// File server to serve static assets
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Load identity providers from the YAML file
	identityProviders, err := LoadIdentityProviders("identiyConfig.yaml")
	if err != nil {
		log.Fatalf("Error loading identity providers: %v", err)
	}

	// Log the loaded identity providers
	for _, provider := range identityProviders {
		log.Printf("Identity Provider Name: %s", provider.Name)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleHome(w, r, identityProviders)
	})

	for _, provider := range identityProviders {
		setupRoutes(provider)
	}
	log.Printf("Starting server ...")
	http.ListenAndServe(":8080", nil)
}
