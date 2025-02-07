package nextauthjwt

import "github.com/gofiber/fiber/v2"

type ErrorCode string

const (
	ErrCodeMissingToken     ErrorCode = "MISSING_TOKEN"
	ErrCodeInvalidToken     ErrorCode = "INVALID_TOKEN"
	ErrCodeTokenExpired     ErrorCode = "TOKEN_EXPIRED"
	ErrCodeCSRFMismatch     ErrorCode = "CSRF_MISMATCH"
	ErrCodeInvalidConfig    ErrorCode = "INVALID_CONFIG"
	ErrCodeMissingCSRF      ErrorCode = "MISSING_CSRF"
	ErrCodeInvalidSignature ErrorCode = "INVALID_SIGNATURE"
)

type AuthError struct {
	StatusCode int
	Message    string
	Code       ErrorCode
	Err        error
}

func (e *AuthError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *AuthError) Unwrap() error {
	return e.Err
}

func NewAuthError(code ErrorCode, msg string, err error) *AuthError {
	statusCode := fiber.StatusUnauthorized
	switch code {
	case ErrCodeInvalidConfig:
		statusCode = fiber.StatusInternalServerError
	case ErrCodeMissingToken, ErrCodeMissingCSRF:
		statusCode = fiber.StatusUnauthorized
	case ErrCodeInvalidToken, ErrCodeTokenExpired, ErrCodeCSRFMismatch, ErrCodeInvalidSignature:
		statusCode = fiber.StatusForbidden
	}

	return &AuthError{
		StatusCode: statusCode,
		Message:    msg,
		Code:       code,
		Err:        err,
	}
}

var (
	ErrMissingToken = NewAuthError(ErrCodeMissingToken, "missing token", nil)
	ErrInvalidToken = NewAuthError(ErrCodeInvalidToken, "invalid token", nil)
	ErrTokenExpired = NewAuthError(ErrCodeTokenExpired, "token expired", nil)
	ErrCSRFMismatch = NewAuthError(ErrCodeCSRFMismatch, "csrf token mismatch", nil)
)
