# About

vpnauth is a self-service portal for user on-boarding and managing their password and TOTP credentials. 

# Configuration

## Gsuite credentials
This is assuming you've completed the 'Gsuite credentials' section in setting up gsuite_auth README. You'll need the client ID and secret from google console to complete the environment variable configuration.

##  Required environment variables

```
VPNAUTH_GSUITE_DOMAIN: your GSuite Org domain
VPNAUTH_DYNAMODB_ACCESS_KEY: an AWS access key with access to VPNAUTH_DYNAMODB_PASSWD_TABLE
VPNAUTH_DYNAMODB_SECRET_KEY: an AWS secret key with access to VPNAUTH_DYNAMODB_PASSWD_TABLE
VPNAUTH_DYNAMODB_REGION: the AWS region your dynamoDB table lives in
VPNAUTH_GOOGLE_CLIENT_ID: the client ID from your webapp oauth2 setup
VPNAUTH_GOOGLE_CLIENT_SECRET: the client secret from your webapp oauth2 setup
```

## Optional environment variables
If VPNAUTH_TOTP_ENCRYPTION_KEY is set, the flow for managing TOTP will be enabled in the interface.

```
VPNAUTH_TOTP_ENCRYPTION_KEY: the decryption key for decrypting entries from VPNAUTH_DYNAMODB_TOTP_TABLE
```

## Override-able environment variables

```
VPNAUTH_OVPN_BASE_DIR: if there are .ovpn files in this directory, they will be listed for download on everyone's homepage, Default: /app/static/ovpn
VPNAUTH_REDIRECT_URI: the callback url used by your webapp, will likely need to be changed to a real domain like https://vpnauth.hi.com/oauth2callback, Default: http://127.0.0.1:5000/oauth2callback
VPNAUTH_GOOGLE_SCOPE: required scopes, probably OK to leave alone, Default: openid%20email%20profile
VPNAUTH_DYNAMODB_PASSWD_TABLE: dynamoDB table where bcrypt password hashes are stored, Default: vpnpasswd
VPNAUTH_DYNAMODB_TOTP_TABLE: dynamoDB table storing encrypted (AES+CBC+Pbkdf2) passwords, Default: vpntotp
VPNAUTH_SQLALCHEMY_DATABASE_URI: database storing user credentials for vpnauth, Default: postgresql+psycopg2://vpnauth:vpnauth@127.0.0.1:5432/vpnauth
VPNAUTH_PBKDF2_ITERATIONS: number of pbkdf2 iterations, probably OK, Default: 15000
```

# DynamoDB tables
See reference from gsuite_auth README

# Docker image
There is a docker image available under the packages section of https://github.com/looprock/openvpn_gsuite_auth
