package main

import (
	"encoding/base64"
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// PasskeyUser implements webauthn.User interface.
type PasskeyUser struct {
	ID          []byte
	Phone       string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *PasskeyUser) WebAuthnID() []byte                         { return u.ID }
func (u *PasskeyUser) WebAuthnName() string                       { return u.Phone }
func (u *PasskeyUser) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// DynamoDB item structs.

type UserItem struct {
	PK          string `dynamodbav:"PK"`
	SK          string `dynamodbav:"SK"`
	UserID      string `dynamodbav:"UserID"`
	Phone       string `dynamodbav:"Phone"`
	DisplayName string `dynamodbav:"DisplayName"`
	CreatedAt   string `dynamodbav:"CreatedAt"`
}

type CredentialItem struct {
	PK           string   `dynamodbav:"PK"`
	SK           string   `dynamodbav:"SK"`
	CredentialID string   `dynamodbav:"CredentialID"`
	PublicKey    string   `dynamodbav:"PublicKey"`
	SignCount    uint32   `dynamodbav:"SignCount"`
	AAGUID       string   `dynamodbav:"AAGUID"`
	Transport    []string `dynamodbav:"Transport"`
	BackupEligible bool     `dynamodbav:"BackupEligible"`
	BackupState    bool     `dynamodbav:"BackupState"`
	UserID         string   `dynamodbav:"UserID"`
	DeviceInfo     string   `dynamodbav:"DeviceInfo,omitempty"`
	CreatedAt      string   `dynamodbav:"CreatedAt,omitempty"`
}

type WrappedKeyItem struct {
	PK         string `dynamodbav:"PK"`
	SK         string `dynamodbav:"SK"`
	WrappedKey string `dynamodbav:"WrappedKey"`
	UpdatedAt  string `dynamodbav:"UpdatedAt"`
}

type NoteItem struct {
	PK         string `dynamodbav:"PK"`
	SK         string `dynamodbav:"SK"`
	Ciphertext string `dynamodbav:"Ciphertext"`
	IV         string `dynamodbav:"IV"`
	UpdatedAt  string `dynamodbav:"UpdatedAt"`
}

type SessionItem struct {
	PK          string `dynamodbav:"PK"`
	SK          string `dynamodbav:"SK"`
	SessionData string `dynamodbav:"SessionData"`
	Phone       string `dynamodbav:"Phone,omitempty"`
	UserID      string `dynamodbav:"UserID,omitempty"`
	TTL         int64  `dynamodbav:"TTL"`
}

type TokenItem struct {
	PK     string `dynamodbav:"PK"`
	SK     string `dynamodbav:"SK"`
	Phone  string `dynamodbav:"Phone"`
	UserID string `dynamodbav:"UserID"`
	TTL    int64  `dynamodbav:"TTL"`
}

type InviteItem struct {
	PK                 string `dynamodbav:"PK"`
	SK                 string `dynamodbav:"SK"`
	InviteID           string `dynamodbav:"InviteID"`
	Phone              string `dynamodbav:"Phone"`
	UserID             string `dynamodbav:"UserID"`
	EncryptedMasterKey string `dynamodbav:"EncryptedMasterKey"`
	Status             string `dynamodbav:"Status"`
	CreatedAt          string `dynamodbav:"CreatedAt"`
	TTL                int64  `dynamodbav:"TTL"`
}

type InviteLinkItem struct {
	PK       string `dynamodbav:"PK"`
	SK       string `dynamodbav:"SK"`
	InviteID string `dynamodbav:"InviteID"`
	TTL      int64  `dynamodbav:"TTL"`
}

type OTPItem struct {
	PK        string `dynamodbav:"PK"`
	SK        string `dynamodbav:"SK"`
	Phone     string `dynamodbav:"Phone"`
	Code      string `dynamodbav:"Code"`
	CreatedAt string `dynamodbav:"CreatedAt"`
	TTL       int64  `dynamodbav:"TTL"`
}

type RateLimitItem struct {
	PK        string `dynamodbav:"PK"`
	SK        string `dynamodbav:"SK"`
	CreatedAt string `dynamodbav:"CreatedAt"`
	TTL       int64  `dynamodbav:"TTL"`
}

// Conversion functions.

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func fromb64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func credentialToItem(phone string, cred *webauthn.Credential, userID string, createdAt string, deviceInfo string) CredentialItem {
	transports := make([]string, len(cred.Transport))
	for i, t := range cred.Transport {
		transports[i] = string(t)
	}
	return CredentialItem{
		PK:             "USER#" + phone,
		SK:             "CRED#" + b64url(cred.ID),
		CredentialID:   b64url(cred.ID),
		PublicKey:      b64url(cred.PublicKey),
		SignCount:      cred.Authenticator.SignCount,
		AAGUID:         b64url(cred.Authenticator.AAGUID),
		Transport:      transports,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		UserID:         userID,
		DeviceInfo:     deviceInfo,
		CreatedAt:      createdAt,
	}
}

func itemToCredential(item CredentialItem) (webauthn.Credential, error) {
	id, err := fromb64url(item.CredentialID)
	if err != nil {
		return webauthn.Credential{}, err
	}
	pk, err := fromb64url(item.PublicKey)
	if err != nil {
		return webauthn.Credential{}, err
	}
	aaguid, err := fromb64url(item.AAGUID)
	if err != nil {
		return webauthn.Credential{}, err
	}
	transports := make([]protocol.AuthenticatorTransport, len(item.Transport))
	for i, t := range item.Transport {
		transports[i] = protocol.AuthenticatorTransport(t)
	}
	return webauthn.Credential{
		ID:        id,
		PublicKey: pk,
		Transport: transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: item.BackupEligible,
			BackupState:    item.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguid,
			SignCount: item.SignCount,
		},
	}, nil
}

func marshalSessionData(sd *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func unmarshalSessionData(s string) (webauthn.SessionData, error) {
	var sd webauthn.SessionData
	err := json.Unmarshal([]byte(s), &sd)
	return sd, err
}
