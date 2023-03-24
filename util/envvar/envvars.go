package envvar

type envVarType string

const (
	IntuitClientId                    envVarType = "INTUIT_CLIENT_ID"
	IntuitClientSecret                           = "INTUIT_CLIENT_SECRET"
	IntuitRedirectUri                            = "INTUIT_REDIRECT_URI"
	IntuitOpenIdConfigurationEndpoint            = "INTUIT_OPEN_ID_CONFIGURATION_ENDPOINT"
	IntuitAccountingApiHost                      = "INTUIT_ACCOUNTING_API_HOST"
	CsrfToken                                    = "CSRF_TOKEN"
	EcryptedCsrfPublicKey                        = "ENCRYPTED_CSRF_PUBLIC_KEY"
	EcryptedCsrfPrivateKey                       = "ENCRYPTED_CSRF_PRIVATE_KEY"
	EcryptedCsrfExpiryMinute                     = "ENCRYPTED_CSRF_EXPIRY_MINUTE"
	EcryptedCsrfCookieName                       = "ENCRYPTED_CSRF_COOKIE_NAME"
)
