package nextauthjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"golang.org/x/crypto/hkdf"
)

// Config holds the configuration for NextAuthJWT middleware
type Config struct {
	// Secret key used for token encryption and validation
	Secret string
	// Name of the session cookie
	CookieName string
	// Whether to set secure flag on cookies
	SecureCookie bool
	// Name of the CSRF cookie
	CSRFCookieName string
	// Name of the CSRF header
	CSRFHeaderName string
	// Whether CSRF protection is enabled
	CSRFEnabled bool
	// HTTP methods that require CSRF validation
	CSRFMethods []string
	// Whether to check token expiry
	CheckExpiry bool
	// Whether token encryption is enabled
	EncryptionEnabled bool
	// Token validator implementation
	TokenValidator TokenValidator
	// Logger implementation
	Logger Logger
}

// TokenValidator defines the interface for token validation
type TokenValidator interface {
	ValidateToken(token string, secret string) (jwt.MapClaims, error)
}

// DefaultTokenValidator implements TokenValidator for v5 tokens
type DefaultTokenValidator struct {
	KeyEncryptionAlgorithm     jwa.KeyEncryptionAlgorithm
	ContentEncryptionAlgorithm jwa.ContentEncryptionAlgorithm
	logger                     Logger
}

func NewDefaultTokenValidator() *DefaultTokenValidator {
	return &DefaultTokenValidator{
		KeyEncryptionAlgorithm:     jwa.DIRECT,
		ContentEncryptionAlgorithm: jwa.A256CBC_HS512,
		logger:                     NewDefaultLogger(LogLevelError),
	}
}

func (v *DefaultTokenValidator) ValidateToken(tokenString, secret string) (jwt.MapClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return nil, NewAuthError(ErrCodeInvalidToken, "invalid token format", nil)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, NewAuthError(ErrCodeInvalidToken, "failed to decode token header", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Enc string `json:"enc"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, NewAuthError(ErrCodeInvalidToken, "failed to parse token header", err)
	}

	v.logger.Debug("Token header: kid=%s, enc=%s, alg=%s", header.Kid, header.Enc, header.Alg)

	keyLength := 64 // A256CBC-HS512 requires 64 bytes
	cookieName := "authjs.session-token"
	salt := []byte(cookieName)
	info := []byte("Auth.js Generated Encryption Key")
	key := deriveKey([]byte(secret), salt, append(info, append([]byte(" ("), append(salt, []byte(")")...)...)...), keyLength)

	v.logger.Debug("Attempting to decrypt v5 token with key length: %d", keyLength)
	v.logger.Debug("Salt: %s", cookieName)
	v.logger.Debug("Info: %s", string(append(info, append([]byte(" ("), append(salt, []byte(")")...)...)...)))
	v.logger.Debug("Key: %x", key)

	decrypted, err := jwe.Decrypt([]byte(tokenString), jwe.WithKey(jwa.DIRECT, key))
	if err != nil {
		return nil, NewAuthError(ErrCodeInvalidToken, "failed to decrypt token", err)
	}

	v.logger.Debug("Decrypted v5 token: %s", string(decrypted))

	var claims jwt.MapClaims
	if err := json.Unmarshal(decrypted, &claims); err != nil {
		return nil, NewAuthError(ErrCodeInvalidToken, "failed to parse token claims", err)
	}

	v.logger.Debug("Parsed v5 claims: %+v", claims)
	return claims, nil
}

type V4TokenValidator struct {
	KeyEncryptionAlgorithm     jwa.KeyEncryptionAlgorithm
	ContentEncryptionAlgorithm jwa.ContentEncryptionAlgorithm
	logger                     Logger
}

func NewV4TokenValidator() *V4TokenValidator {
	return &V4TokenValidator{
		KeyEncryptionAlgorithm:     jwa.DIRECT,
		ContentEncryptionAlgorithm: jwa.A256GCM,
		logger:                     NewDefaultLogger(LogLevelError),
	}
}

func (v *V4TokenValidator) ValidateToken(tokenString, secret string) (jwt.MapClaims, error) {
	keyLength := 32 // A256GCM requires 32 bytes
	salt := []byte("")
	info := []byte("NextAuth.js Generated Encryption Key")
	key := deriveKey([]byte(secret), salt, info, keyLength)

	v.logger.Debug("Attempting to decrypt v4 token with key length: %d", keyLength)
	decrypted, err := jwe.Decrypt([]byte(tokenString), jwe.WithKey(v.KeyEncryptionAlgorithm, key))
	if err != nil {
		return nil, NewAuthError(ErrCodeInvalidToken, "failed to decrypt token", err)
	}

	v.logger.Debug("Decrypted v4 token: %s", string(decrypted))

	var claims jwt.MapClaims
	if err := json.Unmarshal(decrypted, &claims); err != nil {
		return nil, NewAuthError(ErrCodeInvalidToken, "failed to parse token claims", err)
	}

	v.logger.Debug("Parsed v4 claims: %+v", claims)
	return claims, nil
}

func deriveKey(secret, salt, info []byte, length int) []byte {
	hash := sha256.New
	hkdf := hkdf.New(hash, secret, salt, info)
	key := make([]byte, length)
	if _, err := hkdf.Read(key); err != nil {
		panic(err)
	}
	return key
}

type TokenManager struct {
	config      *Config
	csrfManager *CSRFManager
}

func NewTokenManager(config *Config) *TokenManager {
	return &TokenManager{
		config:      config,
		csrfManager: NewCSRFManager(config),
	}
}

func (m *TokenManager) validateToken(tokenString string) (jwt.MapClaims, error) {
	claims, err := m.config.TokenValidator.ValidateToken(tokenString, m.config.Secret)
	if err != nil {
		return nil, err
	}

	if m.config.CheckExpiry {
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return nil, ErrTokenExpired
			}
		}
	}

	return claims, nil
}

func (m *TokenManager) extractToken(c *fiber.Ctx) (string, error) {
	token := c.Cookies(m.config.CookieName)
	if token == "" {
		m.config.Logger.Error("Session token cookie is missing")
		return "", ErrMissingToken
	}
	m.config.Logger.Debug("Successfully extracted session token from cookie")
	return token, nil
}

func (m *TokenManager) shouldValidateCSRF(method string) bool {
	for _, m := range m.config.CSRFMethods {
		if m == method {
			return true
		}
	}
	return false
}

func (m *TokenManager) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token, err := m.extractToken(c)
		if err != nil {
			m.config.Logger.Error("Failed to extract token: %v", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		claims, err := m.validateToken(token)
		if err != nil {
			m.config.Logger.Error("Token validation failed: %v", err)
			statusCode := fiber.StatusUnauthorized
			if err == ErrInvalidToken || err == ErrTokenExpired {
				statusCode = fiber.StatusForbidden
			}
			return c.Status(statusCode).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if m.config.CSRFEnabled && m.shouldValidateCSRF(c.Method()) {
			if err := m.csrfManager.Validate(c); err != nil {
				m.config.Logger.Error("CSRF validation failed: %v", err)
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": err.Error(),
				})
			}
		}

		m.config.Logger.Debug("Successfully validated token for user: %v", claims["sub"])
		m.config.Logger.Debug("Setting claims in context: %+v", claims)
		c.Locals("user", claims)
		return c.Next()
	}
}

// NextAuthJWT is the main middleware struct
type NextAuthJWT struct {
	tokenManager *TokenManager
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	isSecure := os.Getenv("NEXTAUTH_URL") != "" &&
		strings.HasPrefix(os.Getenv("NEXTAUTH_URL"), "https://")

	return Config{
		Secret:            os.Getenv("NEXTAUTH_SECRET"),
		CookieName:        getDefaultV5CookieName(isSecure),
		SecureCookie:      isSecure,
		CSRFCookieName:    getDefaultV5CSRFCookieName(isSecure),
		CSRFHeaderName:    "X-CSRF-Token",
		CSRFEnabled:       true,
		CSRFMethods:       []string{"POST", "PUT", "PATCH", "DELETE"},
		CheckExpiry:       true,
		EncryptionEnabled: true,
		TokenValidator:    NewDefaultTokenValidator(),
		Logger:            NewDefaultLogger(LogLevelError),
	}
}

func getDefaultV5CookieName(isSecure bool) string {
	if isSecure {
		return "__Secure-authjs.session-token"
	}
	return "authjs.session-token"
}

func getDefaultV5CSRFCookieName(isSecure bool) string {
	if isSecure {
		return "__Host-authjs.csrf-token"
	}
	return "authjs.csrf-token"
}

func getDefaultV4CookieName(isSecure bool) string {
	if isSecure {
		return "__Secure-next-auth.session-token"
	}
	return "next-auth.session-token"
}

func getDefaultV4CSRFCookieName(isSecure bool) string {
	if isSecure {
		return "__Host-next-auth.csrf-token"
	}
	return "next-auth.csrf-token"
}

func NewV4Config() Config {
	cfg := DefaultConfig()
	cfg.TokenValidator = NewV4TokenValidator()
	cfg.CookieName = getDefaultV4CookieName(cfg.SecureCookie)
	cfg.CSRFCookieName = getDefaultV4CSRFCookieName(cfg.SecureCookie)
	return cfg
}

func New(config ...Config) *NextAuthJWT {
	cfg := DefaultConfig()

	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.TokenValidator == nil {
		cfg.TokenValidator = &DefaultTokenValidator{}
	}

	if err := cfg.validate(); err != nil {
		panic(err)
	}

	return &NextAuthJWT{
		tokenManager: NewTokenManager(&cfg),
	}
}

// Middleware returns a Fiber middleware handler for authentication
func (n *NextAuthJWT) Middleware() fiber.Handler {
	return n.tokenManager.Middleware()
}

func (c *Config) validate() error {
	if c.Secret == "" {
		return NewAuthError(ErrCodeInvalidConfig, "secret is required", nil)
	}

	if c.CookieName == "" {
		return NewAuthError(ErrCodeInvalidConfig, "cookie name is required", nil)
	}

	if c.CSRFEnabled {
		if c.CSRFCookieName == "" {
			return NewAuthError(ErrCodeInvalidConfig, "csrf cookie name is required when csrf is enabled", nil)
		}
		if c.CSRFHeaderName == "" {
			return NewAuthError(ErrCodeInvalidConfig, "csrf header name is required when csrf is enabled", nil)
		}
		if len(c.CSRFMethods) == 0 {
			return NewAuthError(ErrCodeInvalidConfig, "csrf methods are required when csrf is enabled", nil)
		}
	}

	return nil
}
