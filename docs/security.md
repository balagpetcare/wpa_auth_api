# Security Policy

## Allowed Origins
The API implements strict CORS policy. Only origins defined in `ALLOWED_PUBLIC_ORIGINS` and `ADMIN_PANEL_ORIGIN` are permitted to make cross-origin requests. Requests from unknown origins will be blocked by CORS unless they are server-to-server or mobile app requests (no origin header), which will then be subjected to strict Client ID and redirect URI validations if applicable.

## Redirect URI Validation
For OAuth and authentication flows, all `redirect_uri` parameters provided by connecting clients must strictly match one of the predefined `redirectUris` registered for that specific `clientId`. Any mismatch results in a blocked request and an immediate security audit event.

## Token Storage Policy
Tokens must be stored securely based on the client application type:
- **First-Party Web Apps:** Should store refresh tokens in `HttpOnly, Secure, SameSite=Strict` cookies. Access tokens can be stored in memory.
- **Mobile Applications:** Should leverage secure OS keystores (e.g., iOS Keychain, Android Keystore) to encrypt and persist tokens.
- **Third-Party Integrations:** Must maintain strict confidentiality of the client secret. Third-party applications should only receive short-lived access tokens explicitly consented to by the user.

## Refresh Token Rotation
The system enforces Refresh Token Rotation to mitigate the risk of token theft.
1. Every time a refresh token is used to obtain a new access token, a new refresh token is issued and the old one is revoked.
2. If a revoked refresh token is presented again (indicating potential token theft), the entire family of refresh tokens associated with that user session is instantly invalidated.
