# Passkey TOTP SMS

WebAuthn passkey demo with **phone number + SMS OTP verification** for new user registration, and cross-device passkey linking via QR code.

New users verify phone ownership via a 6-digit SMS OTP (sent via AWS SNS), then create a passkey. Returning users authenticate instantly via passkey (biometric) with no SMS cost. Built on multi-key envelope encryption: a random master key encrypts notes, and each passkey's PRF output wraps a copy of the master key.

- **Frontend**: `https://totp-sms.bkawk.com/` (S3 + CloudFront)
- **API**: `https://api.totp-sms.bkawk.com/` (Go Lambda + API Gateway)

## How It Works

### New User Flow
1. **Enter phone** — select country code + enter phone number
2. **Receive OTP** — 6-digit code sent via SMS (10-minute expiry)
3. **Verify OTP** — enter code to prove phone ownership
4. **Create passkey** — register a WebAuthn credential (biometric)
5. **Logged in** — PRF extension derives wrapping key, master key generated and wrapped

### Returning User Flow
1. **Enter phone** (or use passkey autofill) — no SMS needed
2. **Authenticate** — passkey biometric prompt
3. **Logged in** — PRF unwraps master key, notes decrypted client-side

### Envelope Encryption
1. **Master key** — random AES-GCM-256 key generated client-side on first login
2. **Wrapping** — HKDF-SHA-256 derives a wrapping key from PRF output, which encrypts (AES-KW) the master key; wrapped copy stored server-side per credential
3. **Encrypt/decrypt** — notes encrypted with master key (AES-GCM) before being sent to the server
4. **Add passkeys** — register new passkey, verify with PRF, wrap existing master key with new wrapping key
5. **Any passkey works** — each passkey unwraps its own copy of the master key

### Cross-Device Linking

When a user is authenticated on Device A and wants to add a passkey on Device B (which doesn't have a synced passkey):

```
Device A (authenticated):
  1. Generate random inviteSecret (32 bytes)
  2. Encrypt masterKey with inviteSecret (AES-GCM) -> encryptedMasterKey
  3. POST /invite/create {encryptedMasterKey} -> {inviteId}
  4. Show QR code = https://totp-sms.bkawk.com/?invite=<inviteId>#<inviteSecret>
  5. Poll /invite/status until completed

Device B (scans QR):
  1. Extract inviteId from query, inviteSecret from URL fragment
  2. GET /invite/info -> {maskedPhone, status}
  3. POST /invite/register/begin -> registration challenge
  4. Create passkey (biometric #1)
  5. POST /invite/register/finish -> {token, phone, credentialId, encryptedMasterKey}
  6. Decrypt encryptedMasterKey using inviteSecret -> masterKey
  7. Login ceremony targeting new credential + PRF eval (biometric #2)
  8. Derive wrapping key from PRF, wrap masterKey
  9. PUT /passkeys/wrapped-key -> store wrapped copy
  10. POST /invite/complete -> Device A sees success
```

The invite secret lives only in the URL fragment (`#`), which is never sent to the server per RFC 3986.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/begin` | No | Phone-first flow — returns `otp_required` (new) or login challenge (returning) |
| POST | `/auth/verify-otp` | No | Verify 6-digit OTP code — returns registration challenge |
| POST | `/register/begin` | No | Start registration |
| POST | `/register/finish` | No | Complete registration |
| POST | `/login/begin` | No | Start discoverable login (used by autofill) |
| POST | `/login/finish` | No | Complete login — returns `{token, phone, credentialId}` |
| GET | `/session` | Yes | Validate token |
| POST | `/logout` | Yes | Invalidate token |
| GET | `/note` | Yes | Get encrypted note |
| PUT | `/note` | Yes | Save encrypted note |
| GET | `/passkeys` | Yes | List user's passkeys |
| POST | `/passkeys/add/begin` | Yes | Start add-passkey registration |
| POST | `/passkeys/add/finish` | Yes | Complete add-passkey registration |
| DELETE | `/passkeys` | Yes | Delete a passkey |
| PUT | `/passkeys/wrapped-key` | Yes | Store wrapped master key for a credential |
| GET | `/passkeys/wrapped-key` | Yes | Get wrapped master key for a credential |
| POST | `/invite/create` | Yes | Create cross-device invite |
| GET | `/invite/info` | No | Get masked phone and invite status |
| POST | `/invite/register/begin` | No | Start registration via invite |
| POST | `/invite/register/finish` | No | Complete registration via invite |
| GET | `/invite/status` | Yes | Poll invite status (creator only) |
| POST | `/invite/complete` | Yes | Mark invite as completed |

## DynamoDB Schema (`passkey-totp-sms`)

Single-table design with PK/SK.

| Entity | PK | SK | Key Attributes |
|--------|----|----|----------------|
| User | `USER#<phone>` | `PROFILE` | UserID, Phone, DisplayName, CreatedAt |
| Credential | `USER#<phone>` | `CRED#<credID>` | CredentialID, PublicKey, SignCount, AAGUID, Transport, DeviceInfo, CreatedAt |
| Wrapped Key | `USER#<phone>` | `WRAPKEY#<credID>` | WrappedKey, UpdatedAt |
| OTP | `OTP#<otpId>` | `DATA` | Phone, Code, CreatedAt, TTL (10min) |
| Rate Limit | `RATE#<phone>` | `SMS#<uuid>` | CreatedAt, TTL (1h) |
| Ceremony Session | `SESSION#<challengeID>` | `CHALLENGE` | SessionData, Phone, UserID, TTL (5min) |
| Auth Token | `TOKEN#<hex>` | `AUTH` | Phone, UserID, TTL (24h) |
| Encrypted Note | `USER#<phone>` | `NOTE` | Ciphertext, IV, UpdatedAt |
| Invitation | `INVITE#<inviteId>` | `DATA` | Phone, UserID, EncryptedMasterKey, Status, TTL (5min) |
| Invite Link | `USER#<phone>` | `INVITE#<inviteId>` | InviteID, TTL (for rate-limit counting) |

**GSI `UserID-index`**: PK=`UserID` -- maps userHandle back to phone for discoverable login.

**TTL**: Enabled on `TTL` attribute for automatic session/token/invite/OTP expiry.

## Security

| Threat | Mitigation |
|--------|-----------|
| Server sees master key | Encrypted with inviteSecret; server never receives inviteSecret (URL fragment) |
| Attacker guesses inviteId | UUID v4 = 122 bits entropy |
| QR intercepted | Requires physical proximity; HTTPS encrypts path; fragment not sent in HTTP |
| Invitation replay | Atomic conditional status transitions; single-use |
| OTP brute force | 6-digit code = 1M combinations; consumed atomically on verify; 10-min expiry |
| SMS flood | Rate limit: max 5 OTPs per phone per hour via DynamoDB items with TTL |
| Rate limiting | Max 3 active invites per user; WAF + API Gateway throttling |
| Phone leak via invite/info | Returns masked phone only (e.g. `+44****9041`) |
| Invitation expiry | 5-minute TTL; DynamoDB auto-deletes |

Additional security measures:
- **End-to-end encrypted**: Notes encrypted/decrypted client-side with AES-GCM-256
- **Envelope encryption**: Master key wrapped with AES-KW per credential
- **PRF key derivation**: HKDF-SHA-256 with distinct application salts
- **Atomic session consumption**: Conditional delete prevents replay attacks
- **Atomic OTP consumption**: Conditional delete prevents replay attacks
- **No inline scripts**: CSP `script-src 'self'; style-src 'self'`
- **Security headers**: HSTS, X-Content-Type-Options, Referrer-Policy, frame-ancestors 'none'
- **WAF**: AWS Managed Rules + IP-based rate limiting (1000 req/5min)
- **CORS**: Locked to `https://totp-sms.bkawk.com`

## Architecture

- **Go Lambda** (`passkey-totp-sms-api`) behind **API Gateway HTTP API**
- **DynamoDB** table `passkey-totp-sms` (on-demand, PK/SK single-table design)
- **S3** bucket `totp-sms-bkawk-com` + **CloudFront** distribution
- **Route53** A records for `api.totp-sms.bkawk.com` and `totp-sms.bkawk.com`
- **ACM** certificate (DNS-validated, managed by CDK)
- **SNS** SMS in `eu-west-2` for OTP delivery (UK long code as origination identity)
- Region: `us-east-1`, Account: `238576302016` (profile: `bkawk`)
- All infrastructure managed by **AWS CDK** (TypeScript) in `infra/`

## Infrastructure (CDK)

### Prerequisites

- [Node.js](https://nodejs.org/) (v20+)
- [Go](https://go.dev/) (v1.25+)
- [AWS CLI](https://aws.amazon.com/cli/) configured with profile `bkawk`

### First-Time Setup

```bash
cd infra
npm install
AWS_PROFILE=bkawk npx cdk bootstrap aws://238576302016/us-east-1
```

### Deploy

```bash
cd infra
AWS_PROFILE=bkawk npx cdk deploy
```

### Preview Changes

```bash
cd infra
AWS_PROFILE=bkawk npx cdk diff
```

### Teardown

```bash
cd infra
AWS_PROFILE=bkawk npx cdk destroy
```

Note: DynamoDB table and S3 bucket have `RETAIN` removal policies and will not be deleted by `cdk destroy`.

### SMS Setup (SNS Sandbox)

SMS is sent via SNS in `eu-west-2`. In sandbox mode, destination numbers must be verified:

```bash
# Add a sandbox destination number
AWS_PROFILE=bkawk aws sns create-sms-sandbox-phone-number \
  --phone-number "+447498209041" --region eu-west-2

# Verify with the code received via SMS
AWS_PROFILE=bkawk aws sns verify-sms-sandbox-phone-number \
  --phone-number "+447498209041" --verification-code <code> --region eu-west-2
```

A UK long code phone number is provisioned in `eu-west-2` as the origination identity. A resource policy on the phone number grants SNS permission to use it (required since September 2024).

### Adding an Alphanumeric Sender ID (Optional)

By default, SMS messages show the long code phone number as the sender. To display a branded name (e.g. "AUTHCODE") instead, register a Sender ID via the UK MEF (Mobile Ecosystem Forum) SMS Sender ID Protection Registry.

#### Step 1: Check if the Sender ID is MEF-protected

If another company has already registered the Sender ID with MEF, you need their authorization. If the Sender ID is new/unprotected, the LOA step can be skipped.

#### Step 2: Complete the MEF registration via AWS

Go to the [AWS End User Messaging SMS console](https://console.aws.amazon.com/sms-voice/) in `eu-west-2` and create a new UK Sender ID registration. The form requires:

**Company Info:**

| Field | Example |
|-------|---------|
| Company Name | Your company name |
| Tax ID / Business Registration Number | Company tax ID |
| Company Website | https://your-site.com |
| Address, City, State, Postal Code | Corporate HQ address |
| Country | GB |

**Contact Info:**

| Field | Example |
|-------|---------|
| First Name, Last Name | Business contact name |
| Contact Email | contact@your-company.com |
| Contact Phone Number | +447... |

**Sender ID Info:**

| Field | Notes |
|-------|-------|
| Sender ID | e.g. `AUTHCODE` — alphanumeric, casing must match MEF registration exactly |
| Letter of Authorization (LOA) | Required if MEF-protected. PDF, max 400 KB, dated within last 30 days. Download the template from the registration form. |

**Messaging Use Case:**

| Field | Value for this project |
|-------|----------------------|
| Monthly SMS Volume | Select expected volume |
| Use Case Category | One-time passwords |
| Message Sample 1 | `AUTHCODE: Your verification code is 123456. Valid for 10 min. Reply STOP to opt-out.` |

#### Step 3: Wait for approval

AWS reviews the registration. Turnaround varies.

#### Step 4: Add the Sender ID to the code

Add the `AWS.SNS.SMS.SenderID` message attribute in `api/handlers.go` `sendSMS()`:

```go
"AWS.SNS.SMS.SenderID": {
    DataType:    stringPtr("String"),
    StringValue: stringPtr("AUTHCODE"),
},
```

#### Step 5: Add a resource policy on the Sender ID

```bash
AWS_PROFILE=bkawk aws pinpoint-sms-voice-v2 put-resource-policy \
  --region eu-west-2 \
  --resource-arn "arn:aws:sms-voice:eu-west-2:238576302016:sender-id/AUTHCODE/GB" \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "sns.amazonaws.com"},
      "Action": "sms-voice:SendTextMessage",
      "Resource": "arn:aws:sms-voice:eu-west-2:238576302016:sender-id/AUTHCODE/GB",
      "Condition": {"StringEquals": {"aws:SourceAccount": "238576302016"}}
    }]
  }'
```

#### Step 6: Deploy and test

Note: UK carriers may still override the Sender ID with the long code number depending on carrier policy.

References:
- [UK sender ID registration process](https://docs.aws.amazon.com/sms-voice/latest/userguide/registrations-uk.html)
- [UK sender ID registration form fields](https://docs.aws.amazon.com/sms-voice/latest/userguide/registrations-uk-form.html)

### Exiting SNS Sandbox (Production)

To send SMS to unverified phone numbers:

1. Go to **Amazon SNS Console > Mobile > Text messaging (SMS)** in `eu-west-2`
2. Click **"Exit SMS sandbox"**
3. Fill in the support case:
   - **Use case**: OTP for user authentication
   - **Message type**: One Time Password
   - **Region**: eu-west-2
   - **Countries**: United Kingdom
   - **Template**: `AUTHCODE: Your verification code is XXXXXX. Valid for 10 min. Reply STOP to opt-out.`
4. Request a monthly spend limit increase (e.g. $10-50)
5. Typical approval: ~24 hours
