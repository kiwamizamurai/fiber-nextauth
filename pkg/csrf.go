package nextauthjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/gofiber/fiber/v2"
)

type CSRFManager struct {
	config *Config
}

func NewCSRFManager(config *Config) *CSRFManager {
	return &CSRFManager{
		config: config,
	}
}

func (m *CSRFManager) validateCSRFToken(token, hash string) error {
	if hash != m.generateHash(token) {
		return ErrCSRFMismatch
	}
	return nil
}

func (m *CSRFManager) generateHash(data string) string {
	h := hmac.New(sha256.New, []byte(m.config.Secret))
	h.Write([]byte(data))
	hash := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return hash
}

func (m *CSRFManager) Validate(c *fiber.Ctx) error {
	if !m.config.CSRFEnabled {
		m.config.Logger.Debug("CSRF validation is disabled")
		return nil
	}

	if !contains(m.config.CSRFMethods, c.Method()) {
		m.config.Logger.Debug("Skipping CSRF validation for %s method", c.Method())
		return nil
	}

	csrfCookie := c.Cookies(m.config.CSRFCookieName)
	if csrfCookie == "" {
		m.config.Logger.Error("Missing CSRF cookie")
		return NewAuthError(ErrCodeMissingCSRF, "missing csrf cookie", nil)
	}

	csrfHeader := c.Get(m.config.CSRFHeaderName)
	if csrfHeader == "" {
		m.config.Logger.Error("Missing CSRF header")
		return NewAuthError(ErrCodeMissingCSRF, "missing csrf header", nil)
	}

	parts := strings.Split(csrfCookie, ".")
	if len(parts) != 2 {
		m.config.Logger.Error("Invalid CSRF cookie format")
		return ErrCSRFMismatch
	}

	cookieToken, cookieHash := parts[0], parts[1]
	if err := m.validateCSRFToken(cookieToken, cookieHash); err != nil {
		m.config.Logger.Error("CSRF token validation failed: %v", err)
		return err
	}

	if csrfHeader != cookieToken {
		m.config.Logger.Error("CSRF token mismatch between cookie and header")
		return ErrCSRFMismatch
	}

	m.config.Logger.Debug("CSRF validation successful")
	return nil
}

// contains checks if a string exists in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
