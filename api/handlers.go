package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snsTypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/google/uuid"
)

func authenticateRequest(ctx context.Context, db *dynamodb.Client, headers map[string]string) (*TokenItem, error) {
	auth := headers["authorization"]
	if auth == "" {
		auth = headers["Authorization"]
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("missing bearer token")
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	item, err := getToken(ctx, db, token)
	if err != nil || item == nil {
		return nil, fmt.Errorf("invalid token")
	}
	if item.TTL < time.Now().Unix() {
		return nil, fmt.Errorf("expired token")
	}
	return item, nil
}

var e164Regex = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)

func isValidPhone(phone string) bool {
	return e164Regex.MatchString(phone)
}

func normalizePhone(countryCode string, phone string) string {
	// Strip any spaces, dashes, parens from phone
	phone = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
	// Strip leading zeros from local number
	phone = strings.TrimLeft(phone, "0")
	// Ensure countryCode starts with +
	if !strings.HasPrefix(countryCode, "+") {
		countryCode = "+" + countryCode
	}
	return countryCode + phone
}

func maskPhone(phone string) string {
	// Show country code + last 4 digits, e.g. "+44****0000"
	if len(phone) <= 6 {
		return "****"
	}
	// Find where digits start (after +countrycode)
	// For simplicity: show first 3 chars + **** + last 4
	last4 := phone[len(phone)-4:]
	prefix := phone[:3]
	return prefix + "****" + last4
}

func generateOTPCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func sendSMS(ctx context.Context, client *sns.Client, phone string, message string) error {
	_, err := client.Publish(ctx, &sns.PublishInput{
		PhoneNumber: &phone,
		Message:     &message,
		MessageAttributes: map[string]snsTypes.MessageAttributeValue{
			"AWS.SNS.SMS.SMSType": {
				DataType:    stringPtr("String"),
				StringValue: stringPtr("Transactional"),
			},
		},
	})
	return err
}

func stringPtr(s string) *string { return &s }

func parseDeviceInfo(userAgent string) string {
	if userAgent == "" {
		return "Unknown device"
	}

	var osName string
	switch {
	case strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "iPad") || strings.Contains(userAgent, "iPod"):
		osName = "iOS"
	case strings.Contains(userAgent, "Android"):
		osName = "Android"
	case strings.Contains(userAgent, "CrOS"):
		osName = "ChromeOS"
	case strings.Contains(userAgent, "Macintosh") || strings.Contains(userAgent, "Mac OS"):
		osName = "macOS"
	case strings.Contains(userAgent, "Windows"):
		osName = "Windows"
	case strings.Contains(userAgent, "Linux"):
		osName = "Linux"
	}

	var browser string
	switch {
	case strings.Contains(userAgent, "SamsungBrowser"):
		browser = "Samsung Internet"
	case strings.Contains(userAgent, "OPR") || strings.Contains(userAgent, "Opera"):
		browser = "Opera"
	case strings.Contains(userAgent, "Edg"):
		browser = "Edge"
	case strings.Contains(userAgent, "Chrome") && !strings.Contains(userAgent, "Edg"):
		browser = "Chrome"
	case strings.Contains(userAgent, "Safari") && !strings.Contains(userAgent, "Chrome"):
		browser = "Safari"
	case strings.Contains(userAgent, "Firefox"):
		browser = "Firefox"
	}

	if osName != "" && browser != "" {
		return osName + " / " + browser
	}
	if osName != "" {
		return osName
	}
	if browser != "" {
		return browser
	}
	return "Unknown device"
}

func handleAuthBegin(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn, sms *sns.Client, body string) (events.APIGatewayV2HTTPResponse, error) {
	var req struct {
		Phone       string `json:"phone"`
		CountryCode string `json:"countryCode"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.Phone == "" {
		return jsonResp(400, map[string]string{"error": "phone required"})
	}

	phone := normalizePhone(req.CountryCode, req.Phone)
	if !isValidPhone(phone) {
		return jsonResp(400, map[string]string{"error": "invalid phone number"})
	}

	// Check if user already has credentials
	creds, err := getUserCredentials(ctx, db, phone)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	if len(creds) > 0 {
		// Existing user — build PasskeyUser with credentials for BeginLogin
		userItem, err := getUser(ctx, db, phone)
		if err != nil || userItem == nil {
			return jsonResp(500, map[string]string{"error": "db error"})
		}
		var webauthnCreds []webauthn.Credential
		for _, ci := range creds {
			c, err := itemToCredential(ci)
			if err != nil {
				continue
			}
			webauthnCreds = append(webauthnCreds, c)
		}
		user := &PasskeyUser{
			ID:          []byte(userItem.UserID),
			Phone:       userItem.Phone,
			DisplayName: userItem.DisplayName,
			Credentials: webauthnCreds,
		}

		assertion, session, err := wa.BeginLogin(user)
		if err != nil {
			log.Printf("begin login error: %v", err)
			return jsonResp(500, map[string]string{"error": "login challenge failed"})
		}

		challengeID := uuid.New().String()
		sessionJSON, err := marshalSessionData(session)
		if err != nil {
			return jsonResp(500, map[string]string{"error": "session marshal error"})
		}

		if err := putSession(ctx, db, SessionItem{
			PK:          "SESSION#" + challengeID,
			SK:          "CHALLENGE",
			SessionData: sessionJSON,
			Phone:       phone,
			UserID:      userItem.UserID,
			TTL:         time.Now().Add(5 * time.Minute).Unix(),
		}); err != nil {
			log.Printf("putSession error in authBegin login: %v", err)
			return jsonResp(500, map[string]string{"error": "db error"})
		}

		return jsonResp(200, map[string]interface{}{
			"action":      "login",
			"challengeID": challengeID,
			"options":     assertion,
		})
	}

	// New user — rate-limit check, generate OTP, send SMS
	count, err := countRecentOTPs(ctx, db, phone)
	if err != nil {
		log.Printf("countRecentOTPs error: %v", err)
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if count >= 5 {
		return jsonResp(429, map[string]string{"error": "too many OTP requests, try again later"})
	}

	code, err := generateOTPCode()
	if err != nil {
		return jsonResp(500, map[string]string{"error": "otp generation error"})
	}

	otpID := uuid.New().String()
	now := time.Now()

	if err := putOTP(ctx, db, OTPItem{
		PK:        "OTP#" + otpID,
		SK:        "DATA",
		Phone:     phone,
		Code:      code,
		CreatedAt: now.UTC().Format(time.RFC3339),
		TTL:       now.Add(10 * time.Minute).Unix(),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	// Record rate limit
	if err := putRateLimit(ctx, db, RateLimitItem{
		PK:        "RATE#" + phone,
		SK:        "SMS#" + uuid.New().String(),
		CreatedAt: now.UTC().Format(time.RFC3339),
		TTL:       now.Add(1 * time.Hour).Unix(),
	}); err != nil {
		log.Printf("putRateLimit error: %v", err)
	}

	// Send SMS
	message := fmt.Sprintf("AUTHCODE: Your verification code is %s. Valid for 10 min. Reply STOP to opt-out.", code)
	if err := sendSMS(ctx, sms, phone, message); err != nil {
		log.Printf("sendSMS error: %v", err)
		return jsonResp(500, map[string]string{"error": "failed to send SMS"})
	}

	return jsonResp(200, map[string]interface{}{
		"action": "otp_required",
		"otpId":  otpID,
	})
}

func handleVerifyOTP(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn, body string) (events.APIGatewayV2HTTPResponse, error) {
	var req struct {
		OtpID string `json:"otpId"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.OtpID == "" || req.Code == "" {
		return jsonResp(400, map[string]string{"error": "otpId and code required"})
	}

	// Atomically consume OTP (prevents replay)
	otp, err := consumeOTP(ctx, db, req.OtpID)
	if err != nil || otp == nil {
		return jsonResp(400, map[string]string{"error": "invalid or expired OTP"})
	}
	if otp.TTL < time.Now().Unix() {
		return jsonResp(400, map[string]string{"error": "OTP expired"})
	}
	if subtle.ConstantTimeCompare([]byte(otp.Code), []byte(req.Code)) != 1 {
		log.Printf("failed OTP attempt for phone: %s", maskPhone(otp.Phone))
		return jsonResp(400, map[string]string{"error": "incorrect code"})
	}

	phone := otp.Phone

	// Create registration challenge
	userID := uuid.New().String()
	existing, _ := getUser(ctx, db, phone)
	if existing != nil {
		userID = existing.UserID
	}

	user := &PasskeyUser{
		ID:          []byte(userID),
		Phone:       phone,
		DisplayName: phone,
		Credentials: nil,
	}

	creation, session, err := wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		log.Printf("begin registration error: %v", err)
		return jsonResp(500, map[string]string{"error": "registration challenge failed"})
	}

	challengeID := uuid.New().String()
	sessionJSON, err := marshalSessionData(session)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "session marshal error"})
	}

	if err := putSession(ctx, db, SessionItem{
		PK:          "SESSION#" + challengeID,
		SK:          "CHALLENGE",
		SessionData: sessionJSON,
		Phone:       phone,
		UserID:      userID,
		TTL:         time.Now().Add(5 * time.Minute).Unix(),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]interface{}{
		"action":      "register",
		"challengeID": challengeID,
		"options":     creation,
	})
}



func handleRegisterFinish(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn, body string, headers map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	var req struct {
		ChallengeID string          `json:"challengeID"`
		Credential  json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.ChallengeID == "" {
		return jsonResp(400, map[string]string{"error": "challengeID and credential required"})
	}

	// Atomically consume session (prevents replay)
	sess, err := consumeSession(ctx, db, req.ChallengeID)
	if err != nil || sess == nil {
		return jsonResp(400, map[string]string{"error": "invalid or expired session"})
	}
	if sess.TTL < time.Now().Unix() {
		return jsonResp(400, map[string]string{"error": "invalid or expired session"})
	}

	sessionData, err := unmarshalSessionData(sess.SessionData)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "session data error"})
	}

	// Parse credential
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(string(req.Credential)))
	if err != nil {
		log.Printf("parse credential error: %v", err)
		return jsonResp(400, map[string]string{"error": "invalid credential"})
	}

	user := &PasskeyUser{
		ID:          []byte(sess.UserID),
		Phone:       sess.Phone,
		DisplayName: sess.Phone,
		Credentials: nil,
	}

	cred, err := wa.CreateCredential(user, sessionData, parsed)
	if err != nil {
		log.Printf("create credential error: %v", err)
		return jsonResp(400, map[string]string{"error": "credential verification failed"})
	}

	// Create user profile now that credential is verified
	if err := putUser(ctx, db, UserItem{
		PK:          "USER#" + sess.Phone,
		SK:          "PROFILE",
		UserID:      sess.UserID,
		Phone:       sess.Phone,
		DisplayName: sess.Phone,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	// Store credential
	deviceInfo := parseDeviceInfo(headers["user-agent"])
	credItem := credentialToItem(sess.Phone, cred, sess.UserID, time.Now().UTC().Format(time.RFC3339), deviceInfo)
	if err := putCredential(ctx, db, credItem); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	// Generate auth token
	token, err := generateToken()
	if err != nil {
		return jsonResp(500, map[string]string{"error": "token generation error"})
	}
	if err := putToken(ctx, db, TokenItem{
		PK:     "TOKEN#" + token,
		SK:     "AUTH",
		Phone:  sess.Phone,
		UserID: sess.UserID,
		TTL:    time.Now().Add(24 * time.Hour).Unix(),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]interface{}{
		"token": token,
		"phone": sess.Phone,
	})
}

func handleLoginBegin(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn) (events.APIGatewayV2HTTPResponse, error) {
	assertion, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		log.Printf("begin login error: %v", err)
		return jsonResp(500, map[string]string{"error": "login challenge failed"})
	}

	challengeID := uuid.New().String()
	sessionJSON, err := marshalSessionData(session)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "session marshal error"})
	}

	if err := putSession(ctx, db, SessionItem{
		PK:          "SESSION#" + challengeID,
		SK:          "CHALLENGE",
		SessionData: sessionJSON,
		TTL:         time.Now().Add(5 * time.Minute).Unix(),
	}); err != nil {
		log.Printf("putSession error in loginBegin: %v", err)
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]interface{}{
		"challengeID": challengeID,
		"options":     assertion,
	})
}

func handleLoginFinish(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn, body string) (events.APIGatewayV2HTTPResponse, error) {
	var req struct {
		ChallengeID string          `json:"challengeID"`
		Credential  json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.ChallengeID == "" {
		return jsonResp(400, map[string]string{"error": "challengeID and credential required"})
	}

	// Atomically consume session (prevents replay)
	sess, err := consumeSession(ctx, db, req.ChallengeID)
	if err != nil || sess == nil {
		return jsonResp(400, map[string]string{"error": "invalid or expired session"})
	}
	if sess.TTL < time.Now().Unix() {
		return jsonResp(400, map[string]string{"error": "invalid or expired session"})
	}

	sessionData, err := unmarshalSessionData(sess.SessionData)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "session data error"})
	}

	// Parse assertion
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(string(req.Credential)))
	if err != nil {
		log.Printf("parse assertion error: %v", err)
		return jsonResp(400, map[string]string{"error": "invalid credential"})
	}

	var user webauthn.User
	var cred *webauthn.Credential

	if sess.Phone != "" {
		// Phone-first flow (BeginLogin with allowCredentials)
		credItems, err := getUserCredentials(ctx, db, sess.Phone)
		if err != nil {
			return jsonResp(500, map[string]string{"error": "db error"})
		}
		var webauthnCreds []webauthn.Credential
		for _, ci := range credItems {
			c, err := itemToCredential(ci)
			if err != nil {
				continue
			}
			webauthnCreds = append(webauthnCreds, c)
		}
		passkeyUser := &PasskeyUser{
			ID:          []byte(sess.UserID),
			Phone:       sess.Phone,
			DisplayName: sess.Phone,
			Credentials: webauthnCreds,
		}
		cred, err = wa.ValidateLogin(passkeyUser, sessionData, parsed)
		if err != nil {
			log.Printf("login failed: %v", err)
			return jsonResp(401, map[string]string{"error": "authentication failed"})
		}
		user = passkeyUser
	} else {
		// Discoverable login (autofill flow)
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			userIDStr := string(userHandle)
			userItem, err := getUserByUserID(ctx, db, userIDStr)
			if err != nil || userItem == nil {
				return nil, fmt.Errorf("user not found for handle")
			}
			credItems, err := getUserCredentials(ctx, db, userItem.Phone)
			if err != nil {
				return nil, fmt.Errorf("failed to load credentials")
			}
			var creds []webauthn.Credential
			for _, ci := range credItems {
				c, err := itemToCredential(ci)
				if err != nil {
					continue
				}
				creds = append(creds, c)
			}
			return &PasskeyUser{
				ID:          []byte(userItem.UserID),
				Phone:       userItem.Phone,
				DisplayName: userItem.DisplayName,
				Credentials: creds,
			}, nil
		}
		var validatedUser webauthn.User
		validatedUser, cred, err = wa.ValidatePasskeyLogin(handler, sessionData, parsed)
		if err != nil {
			log.Printf("login failed: %v", err)
			return jsonResp(401, map[string]string{"error": "authentication failed"})
		}
		user = validatedUser
	}

	// Update sign count
	phone := user.WebAuthnName()
	credIDStr := b64url(cred.ID)
	if err := updateCredentialSignCount(ctx, db, phone, credIDStr, cred.Authenticator.SignCount); err != nil {
		log.Printf("updateCredentialSignCount error: %v", err)
	}

	// Generate auth token
	token, err := generateToken()
	if err != nil {
		return jsonResp(500, map[string]string{"error": "token generation error"})
	}
	if err := putToken(ctx, db, TokenItem{
		PK:     "TOKEN#" + token,
		SK:     "AUTH",
		Phone:  phone,
		UserID: string(user.WebAuthnID()),
		TTL:    time.Now().Add(24 * time.Hour).Unix(),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]interface{}{
		"token":        token,
		"phone":        phone,
		"credentialId": credIDStr,
	})
}

func handleSession(ctx context.Context, db *dynamodb.Client, headers map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	item, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	return jsonResp(200, map[string]interface{}{
		"phone":         item.Phone,
		"authenticated": true,
	})
}

func handleLogout(ctx context.Context, db *dynamodb.Client, headers map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	auth := headers["authorization"]
	if auth == "" {
		auth = headers["Authorization"]
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	if err := deleteToken(ctx, db, token); err != nil {
		log.Printf("deleteToken error: %v", err)
	}

	return jsonResp(200, map[string]string{"status": "logged out"})
}

func handleGetNote(ctx context.Context, db *dynamodb.Client, headers map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	item, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	note, err := getNote(ctx, db, item.Phone)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if note == nil {
		return jsonResp(200, map[string]interface{}{
			"exists": false,
		})
	}

	return jsonResp(200, map[string]interface{}{
		"exists":     true,
		"ciphertext": note.Ciphertext,
		"iv":         note.IV,
		"updatedAt":  note.UpdatedAt,
	})
}

func handlePutNote(ctx context.Context, db *dynamodb.Client, headers map[string]string, body string) (events.APIGatewayV2HTTPResponse, error) {
	item, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	var req struct {
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.Ciphertext == "" || req.IV == "" {
		return jsonResp(400, map[string]string{"error": "ciphertext and iv required"})
	}

	// Validate IV is exactly 12 bytes (16 base64url chars)
	ivBytes, err := fromb64url(req.IV)
	if err != nil || len(ivBytes) != 12 {
		return jsonResp(400, map[string]string{"error": "iv must be 12 bytes"})
	}

	// Limit ciphertext to 100KB
	if len(req.Ciphertext) > 100*1024 {
		return jsonResp(400, map[string]string{"error": "ciphertext too large"})
	}

	if err := putNote(ctx, db, NoteItem{
		PK:         "USER#" + item.Phone,
		SK:         "NOTE",
		Ciphertext: req.Ciphertext,
		IV:         req.IV,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]string{"status": "saved"})
}

// -- Passkey management handlers --

func handleListPasskeys(ctx context.Context, db *dynamodb.Client, headers map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	token, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	creds, err := getUserCredentials(ctx, db, token.Phone)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	// Fetch all wrapped keys for this user to check status per credential
	wrappedKeys, err := getUserWrappedKeys(ctx, db, token.Phone)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	wkSet := make(map[string]bool, len(wrappedKeys))
	for _, wk := range wrappedKeys {
		// SK is "WRAPKEY#<credID>", extract credID
		if len(wk.SK) > 8 {
			wkSet[wk.SK[8:]] = true
		}
	}

	type passkeyInfo struct {
		CredentialID   string   `json:"credentialId"`
		AAGUID         string   `json:"aaguid"`
		Transport      []string `json:"transport"`
		BackupEligible bool     `json:"backupEligible"`
		BackupState    bool     `json:"backupState"`
		SignCount      uint32   `json:"signCount"`
		CreatedAt      string   `json:"createdAt"`
		DeviceInfo     string   `json:"deviceInfo"`
		HasWrappedKey  bool     `json:"hasWrappedKey"`
	}

	passkeys := make([]passkeyInfo, 0, len(creds))
	for _, c := range creds {
		passkeys = append(passkeys, passkeyInfo{
			CredentialID:   c.CredentialID,
			AAGUID:         c.AAGUID,
			Transport:      c.Transport,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
			SignCount:      c.SignCount,
			CreatedAt:      c.CreatedAt,
			DeviceInfo:     c.DeviceInfo,
			HasWrappedKey:  wkSet[c.CredentialID],
		})
	}

	return jsonResp(200, map[string]interface{}{
		"passkeys": passkeys,
	})
}

func handleAddPasskeyBegin(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn, headers map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	token, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	userItem, err := getUser(ctx, db, token.Phone)
	if err != nil || userItem == nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	credItems, err := getUserCredentials(ctx, db, token.Phone)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if len(credItems) >= 10 {
		return jsonResp(409, map[string]string{"error": "maximum passkey limit reached"})
	}

	var existingCreds []webauthn.Credential
	for _, ci := range credItems {
		c, err := itemToCredential(ci)
		if err != nil {
			continue
		}
		existingCreds = append(existingCreds, c)
	}

	user := &PasskeyUser{
		ID:          []byte(userItem.UserID),
		Phone:       userItem.Phone,
		DisplayName: userItem.DisplayName,
		Credentials: existingCreds,
	}

	excludeList := make([]protocol.CredentialDescriptor, len(existingCreds))
	for i, c := range existingCreds {
		excludeList[i] = protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    c.ID,
			Transport:       c.Transport,
		}
	}

	creation, session, err := wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(excludeList),
	)
	if err != nil {
		log.Printf("begin add passkey error: %v", err)
		return jsonResp(500, map[string]string{"error": "registration challenge failed"})
	}

	challengeID := uuid.New().String()
	sessionJSON, err := marshalSessionData(session)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "session marshal error"})
	}

	if err := putSession(ctx, db, SessionItem{
		PK:          "SESSION#" + challengeID,
		SK:          "CHALLENGE",
		SessionData: sessionJSON,
		Phone:       token.Phone,
		UserID:      userItem.UserID,
		TTL:         time.Now().Add(5 * time.Minute).Unix(),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]interface{}{
		"challengeID": challengeID,
		"options":     creation,
	})
}

func handleAddPasskeyFinish(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn, headers map[string]string, body string) (events.APIGatewayV2HTTPResponse, error) {
	token, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	var req struct {
		ChallengeID string          `json:"challengeID"`
		Credential  json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.ChallengeID == "" {
		return jsonResp(400, map[string]string{"error": "challengeID and credential required"})
	}

	// Atomically consume session (prevents replay)
	sess, err := consumeSession(ctx, db, req.ChallengeID)
	if err != nil || sess == nil {
		return jsonResp(400, map[string]string{"error": "invalid or expired session"})
	}
	if sess.TTL < time.Now().Unix() {
		return jsonResp(400, map[string]string{"error": "invalid or expired session"})
	}
	if sess.Phone != token.Phone {
		return jsonResp(403, map[string]string{"error": "session mismatch"})
	}

	sessionData, err := unmarshalSessionData(sess.SessionData)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "session data error"})
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(string(req.Credential)))
	if err != nil {
		log.Printf("parse credential error: %v", err)
		return jsonResp(400, map[string]string{"error": "invalid credential"})
	}

	user := &PasskeyUser{
		ID:          []byte(sess.UserID),
		Phone:       sess.Phone,
		DisplayName: sess.Phone,
	}

	cred, err := wa.CreateCredential(user, sessionData, parsed)
	if err != nil {
		log.Printf("create credential error: %v", err)
		return jsonResp(400, map[string]string{"error": "credential verification failed"})
	}

	deviceInfo := parseDeviceInfo(headers["user-agent"])
	credItem := credentialToItem(sess.Phone, cred, sess.UserID, time.Now().UTC().Format(time.RFC3339), deviceInfo)
	if err := putCredential(ctx, db, credItem); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]interface{}{
		"status":       "added",
		"credentialId": b64url(cred.ID),
	})
}

func handleStoreWrappedKey(ctx context.Context, db *dynamodb.Client, headers map[string]string, body string) (events.APIGatewayV2HTTPResponse, error) {
	token, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	var req struct {
		CredentialID string `json:"credentialId"`
		WrappedKey   string `json:"wrappedKey"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.CredentialID == "" || req.WrappedKey == "" {
		return jsonResp(400, map[string]string{"error": "credentialId and wrappedKey required"})
	}

	if len(req.WrappedKey) > 200 {
		return jsonResp(400, map[string]string{"error": "wrappedKey too large"})
	}

	// Verify credential belongs to user
	creds, err := getUserCredentials(ctx, db, token.Phone)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	found := false
	for _, c := range creds {
		if c.CredentialID == req.CredentialID {
			found = true
			break
		}
	}
	if !found {
		return jsonResp(404, map[string]string{"error": "credential not found"})
	}

	if err := putWrappedKey(ctx, db, WrappedKeyItem{
		PK:         "USER#" + token.Phone,
		SK:         "WRAPKEY#" + req.CredentialID,
		WrappedKey: req.WrappedKey,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]string{"status": "stored"})
}

func handleGetWrappedKey(ctx context.Context, db *dynamodb.Client, headers map[string]string, queryParams map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	token, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	credID := queryParams["credentialId"]
	if credID == "" {
		return jsonResp(400, map[string]string{"error": "credentialId required"})
	}

	item, err := getWrappedKey(ctx, db, token.Phone, credID)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if item == nil {
		return jsonResp(200, map[string]interface{}{
			"exists": false,
		})
	}

	return jsonResp(200, map[string]interface{}{
		"exists":     true,
		"wrappedKey": item.WrappedKey,
	})
}

func handleDeletePasskey(ctx context.Context, db *dynamodb.Client, headers map[string]string, body string) (events.APIGatewayV2HTTPResponse, error) {
	token, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	var req struct {
		CredentialID string `json:"credentialId"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.CredentialID == "" {
		return jsonResp(400, map[string]string{"error": "credentialId required"})
	}

	creds, err := getUserCredentials(ctx, db, token.Phone)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	if len(creds) <= 1 {
		return jsonResp(409, map[string]string{"error": "cannot delete last passkey"})
	}

	found := false
	for _, c := range creds {
		if c.CredentialID == req.CredentialID {
			found = true
			break
		}
	}
	if !found {
		return jsonResp(404, map[string]string{"error": "credential not found"})
	}

	if err := deleteCredential(ctx, db, token.Phone, req.CredentialID); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if err := deleteWrappedKey(ctx, db, token.Phone, req.CredentialID); err != nil {
		log.Printf("deleteWrappedKey error: %v", err)
	}

	return jsonResp(200, map[string]string{"status": "deleted"})
}

// -- Invitation handlers --

func handleInviteCreate(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn, headers map[string]string, body string) (events.APIGatewayV2HTTPResponse, error) {
	token, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	var req struct {
		EncryptedMasterKey string `json:"encryptedMasterKey"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.EncryptedMasterKey == "" {
		return jsonResp(400, map[string]string{"error": "encryptedMasterKey required"})
	}
	if len(req.EncryptedMasterKey) > 200 {
		return jsonResp(400, map[string]string{"error": "encryptedMasterKey too large"})
	}

	count, err := countActiveInvites(ctx, db, token.Phone)
	if err != nil {
		log.Printf("countActiveInvites error: %v", err)
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	log.Printf("active invites for %s: %d", maskPhone(token.Phone), count)
	if count >= 3 {
		return jsonResp(429, map[string]string{"error": "too many active invites"})
	}

	inviteID := uuid.New().String()
	now := time.Now()
	invite := InviteItem{
		PK:                 "INVITE#" + inviteID,
		SK:                 "DATA",
		InviteID:           inviteID,
		Phone:              token.Phone,
		UserID:             token.UserID,
		EncryptedMasterKey: req.EncryptedMasterKey,
		Status:             "pending",
		CreatedAt:          now.UTC().Format(time.RFC3339),
		TTL:                now.Add(5 * time.Minute).Unix(),
	}

	if err := putInviteWithUserLink(ctx, db, invite); err != nil {
		log.Printf("putInviteWithUserLink error: %v", err)
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]interface{}{
		"inviteId": inviteID,
	})
}

func handleInviteInfo(ctx context.Context, db *dynamodb.Client, queryParams map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	inviteID := queryParams["inviteId"]
	if inviteID == "" {
		return jsonResp(400, map[string]string{"error": "inviteId required"})
	}

	invite, err := getInvite(ctx, db, inviteID)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if invite == nil || invite.TTL < time.Now().Unix() {
		return jsonResp(404, map[string]string{"error": "invite not found or expired"})
	}

	return jsonResp(200, map[string]interface{}{
		"phone":  maskPhone(invite.Phone),
		"status": invite.Status,
	})
}

func handleInviteRegisterBegin(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn, body string) (events.APIGatewayV2HTTPResponse, error) {
	var req struct {
		InviteID string `json:"inviteId"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.InviteID == "" {
		return jsonResp(400, map[string]string{"error": "inviteId required"})
	}

	invite, err := getInvite(ctx, db, req.InviteID)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if invite == nil || invite.TTL < time.Now().Unix() {
		return jsonResp(404, map[string]string{"error": "invite not found or expired"})
	}
	if invite.Status != "pending" {
		return jsonResp(409, map[string]string{"error": "invite already used"})
	}

	user := &PasskeyUser{
		ID:          []byte(invite.UserID),
		Phone:       invite.Phone,
		DisplayName: invite.Phone,
	}

	creation, session, err := wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		log.Printf("invite begin registration error: %v", err)
		return jsonResp(500, map[string]string{"error": "registration challenge failed"})
	}

	challengeID := uuid.New().String()
	sessionJSON, err := marshalSessionData(session)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "session marshal error"})
	}

	if err := putSession(ctx, db, SessionItem{
		PK:          "SESSION#" + challengeID,
		SK:          "CHALLENGE",
		SessionData: sessionJSON,
		Phone:       invite.Phone,
		UserID:      invite.UserID,
		TTL:         time.Now().Add(5 * time.Minute).Unix(),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]interface{}{
		"challengeID": challengeID,
		"options":     creation,
	})
}

func handleInviteRegisterFinish(ctx context.Context, db *dynamodb.Client, wa *webauthn.WebAuthn, body string, headers map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	var req struct {
		InviteID    string          `json:"inviteId"`
		ChallengeID string          `json:"challengeID"`
		Credential  json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.InviteID == "" || req.ChallengeID == "" {
		return jsonResp(400, map[string]string{"error": "inviteId, challengeID, and credential required"})
	}

	invite, err := getInvite(ctx, db, req.InviteID)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if invite == nil || invite.TTL < time.Now().Unix() {
		return jsonResp(404, map[string]string{"error": "invite not found or expired"})
	}
	if invite.Status != "pending" {
		return jsonResp(409, map[string]string{"error": "invite already used"})
	}

	// Atomically consume session
	sess, err := consumeSession(ctx, db, req.ChallengeID)
	if err != nil || sess == nil {
		return jsonResp(400, map[string]string{"error": "invalid or expired session"})
	}
	if sess.TTL < time.Now().Unix() {
		return jsonResp(400, map[string]string{"error": "invalid or expired session"})
	}
	if sess.Phone != invite.Phone || sess.UserID != invite.UserID {
		return jsonResp(403, map[string]string{"error": "session mismatch"})
	}

	sessionData, err := unmarshalSessionData(sess.SessionData)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "session data error"})
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(string(req.Credential)))
	if err != nil {
		log.Printf("invite parse credential error: %v", err)
		return jsonResp(400, map[string]string{"error": "invalid credential"})
	}

	user := &PasskeyUser{
		ID:          []byte(sess.UserID),
		Phone:       sess.Phone,
		DisplayName: sess.Phone,
	}

	cred, err := wa.CreateCredential(user, sessionData, parsed)
	if err != nil {
		log.Printf("invite create credential error: %v", err)
		return jsonResp(400, map[string]string{"error": "credential verification failed"})
	}

	deviceInfo := parseDeviceInfo(headers["user-agent"])
	credItem := credentialToItem(sess.Phone, cred, sess.UserID, time.Now().UTC().Format(time.RFC3339), deviceInfo)
	if err := putCredential(ctx, db, credItem); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	// Atomic status transition
	if err := updateInviteStatus(ctx, db, req.InviteID, "pending", "registered"); err != nil {
		log.Printf("updateInviteStatus error: %v", err)
		return jsonResp(409, map[string]string{"error": "invite already used"})
	}

	// Generate auth token for Device B
	authToken, err := generateToken()
	if err != nil {
		return jsonResp(500, map[string]string{"error": "token generation error"})
	}
	if err := putToken(ctx, db, TokenItem{
		PK:     "TOKEN#" + authToken,
		SK:     "AUTH",
		Phone:  sess.Phone,
		UserID: sess.UserID,
		TTL:    time.Now().Add(24 * time.Hour).Unix(),
	}); err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}

	return jsonResp(200, map[string]interface{}{
		"token":              authToken,
		"phone":              sess.Phone,
		"credentialId":       b64url(cred.ID),
		"encryptedMasterKey": invite.EncryptedMasterKey,
	})
}

func handleInviteStatus(ctx context.Context, db *dynamodb.Client, headers map[string]string, queryParams map[string]string) (events.APIGatewayV2HTTPResponse, error) {
	token, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	inviteID := queryParams["inviteId"]
	if inviteID == "" {
		return jsonResp(400, map[string]string{"error": "inviteId required"})
	}

	invite, err := getInvite(ctx, db, inviteID)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if invite == nil {
		return jsonResp(404, map[string]string{"error": "invite not found"})
	}
	if invite.Phone != token.Phone {
		return jsonResp(403, map[string]string{"error": "forbidden"})
	}

	expired := invite.TTL < time.Now().Unix()

	return jsonResp(200, map[string]interface{}{
		"status":  invite.Status,
		"expired": expired,
	})
}

func handleInviteComplete(ctx context.Context, db *dynamodb.Client, headers map[string]string, body string) (events.APIGatewayV2HTTPResponse, error) {
	token, err := authenticateRequest(ctx, db, headers)
	if err != nil {
		return jsonResp(401, map[string]string{"error": "unauthorized"})
	}

	var req struct {
		InviteID string `json:"inviteId"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.InviteID == "" {
		return jsonResp(400, map[string]string{"error": "inviteId required"})
	}

	invite, err := getInvite(ctx, db, req.InviteID)
	if err != nil {
		return jsonResp(500, map[string]string{"error": "db error"})
	}
	if invite == nil {
		return jsonResp(404, map[string]string{"error": "invite not found"})
	}
	if invite.Phone != token.Phone {
		return jsonResp(403, map[string]string{"error": "forbidden"})
	}

	if err := updateInviteStatus(ctx, db, req.InviteID, "registered", "completed"); err != nil {
		log.Printf("invite complete status update error: %v", err)
		return jsonResp(409, map[string]string{"error": "invalid status transition"})
	}

	return jsonResp(200, map[string]interface{}{
		"status": "completed",
	})
}

// Helpers

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func jsonResp(status int, body interface{}) (events.APIGatewayV2HTTPResponse, error) {
	data, _ := json.Marshal(body)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: status,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(data),
	}, nil
}
