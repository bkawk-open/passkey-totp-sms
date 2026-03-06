package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	dbClient  *dynamodb.Client
	smsClient *sns.Client
	webAuthn  *webauthn.WebAuthn
)

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("unable to load AWS config: %v", err)
	}
	dbClient = dynamodb.NewFromConfig(cfg)

	// SNS client in eu-west-2 for SMS
	smsRegion := os.Getenv("SMS_REGION")
	if smsRegion == "" {
		smsRegion = "eu-west-2"
	}
	smsCfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(smsRegion))
	if err != nil {
		log.Fatalf("unable to load SMS config: %v", err)
	}
	smsClient = sns.NewFromConfig(smsCfg)

	webAuthn, err = newWebAuthn()
	if err != nil {
		log.Fatalf("unable to init webauthn: %v", err)
	}
}

var allowedOrigins = map[string]bool{
	"https://totp-sms.bkawk.com": true,
}

func handler(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	origin := request.Headers["origin"]

	// Handle CORS preflight
	if request.RequestContext.HTTP.Method == "OPTIONS" {
		return corsResponse(events.APIGatewayV2HTTPResponse{StatusCode: 204}, origin), nil
	}

	var resp events.APIGatewayV2HTTPResponse
	var err error

	route := request.RequestContext.HTTP.Method + " " + request.RawPath
	switch route {
	case "POST /auth/begin":
		resp, err = handleAuthBegin(ctx, dbClient, webAuthn, smsClient, request.Body)
	case "POST /auth/verify-otp":
		resp, err = handleVerifyOTP(ctx, dbClient, webAuthn, request.Body)
	case "POST /register/finish":
		resp, err = handleRegisterFinish(ctx, dbClient, webAuthn, request.Body, request.Headers)
	case "POST /login/begin":
		resp, err = handleLoginBegin(ctx, dbClient, webAuthn)
	case "POST /login/finish":
		resp, err = handleLoginFinish(ctx, dbClient, webAuthn, request.Body)
	case "GET /session":
		resp, err = handleSession(ctx, dbClient, request.Headers)
	case "POST /logout":
		resp, err = handleLogout(ctx, dbClient, request.Headers)
	case "GET /note":
		resp, err = handleGetNote(ctx, dbClient, request.Headers)
	case "PUT /note":
		resp, err = handlePutNote(ctx, dbClient, request.Headers, request.Body)
	case "GET /passkeys":
		resp, err = handleListPasskeys(ctx, dbClient, request.Headers)
	case "POST /passkeys/add/begin":
		resp, err = handleAddPasskeyBegin(ctx, dbClient, webAuthn, request.Headers)
	case "POST /passkeys/add/finish":
		resp, err = handleAddPasskeyFinish(ctx, dbClient, webAuthn, request.Headers, request.Body)
	case "DELETE /passkeys":
		resp, err = handleDeletePasskey(ctx, dbClient, request.Headers, request.Body)
	case "PUT /passkeys/wrapped-key":
		resp, err = handleStoreWrappedKey(ctx, dbClient, request.Headers, request.Body)
	case "GET /passkeys/wrapped-key":
		resp, err = handleGetWrappedKey(ctx, dbClient, request.Headers, request.QueryStringParameters)
	case "POST /invite/create":
		resp, err = handleInviteCreate(ctx, dbClient, webAuthn, request.Headers, request.Body)
	case "GET /invite/info":
		resp, err = handleInviteInfo(ctx, dbClient, request.QueryStringParameters)
	case "POST /invite/register/begin":
		resp, err = handleInviteRegisterBegin(ctx, dbClient, webAuthn, request.Body)
	case "POST /invite/register/finish":
		resp, err = handleInviteRegisterFinish(ctx, dbClient, webAuthn, request.Body, request.Headers)
	case "GET /invite/status":
		resp, err = handleInviteStatus(ctx, dbClient, request.Headers, request.QueryStringParameters)
	case "POST /invite/complete":
		resp, err = handleInviteComplete(ctx, dbClient, request.Headers, request.Body)
	default:
		resp, _ = jsonResp(404, map[string]string{"error": "not found"})
	}

	if err != nil {
		log.Printf("handler error on %s: %v", route, err)
		return corsResponse(events.APIGatewayV2HTTPResponse{StatusCode: 500}, origin), nil
	}

	return corsResponse(resp, origin), nil
}

func corsResponse(resp events.APIGatewayV2HTTPResponse, origin string) events.APIGatewayV2HTTPResponse {
	if resp.Headers == nil {
		resp.Headers = make(map[string]string)
	}
	if allowedOrigins[origin] {
		resp.Headers["Access-Control-Allow-Origin"] = origin
		resp.Headers["Vary"] = "Origin"
	}
	resp.Headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
	resp.Headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
	resp.Headers["X-Content-Type-Options"] = "nosniff"
	return resp
}

func main() {
	lambda.Start(handler)
}
