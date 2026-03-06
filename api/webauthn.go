package main

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

func newWebAuthn() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          "totp-sms.bkawk.com",
		RPDisplayName: "Passkey TOTP SMS",
		RPOrigins:     []string{"https://totp-sms.bkawk.com"},
	})
}
