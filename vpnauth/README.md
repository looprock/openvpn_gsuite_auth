# About

vpnauth is a self-service portal for user on-boarding and managing their password and TOTP credentials.

# Installation

## Required environment variables

```VPNAUTH_GSUITE_DOMAIN
VPNAUTH_DYNAMODB_ACCESS_KEY
VPNAUTH_DYNAMODB_SECRET_KEY
VPNAUTH_DYNAMODB_REGION
VPNAUTH_GOOGLE_CLIENT_ID
VPNAUTH_GOOGLE_CLIENT_SECRET
VPNAUTH_TOPT_ENCRYPTION_KEY
```

## Override-able environment variables

```VPNAUTH_REDIRECT_URI, Default: http://127.0.0.1:5000/oauth2callback
VPNAUTH_GOOGLE_SCOPE, Default: openid%20email%20profile
VPNAUTH_DYNAMODB_PASSWD_TABLE, Default: vpnpasswd
VPNAUTH_DYNAMODB_TOPT_TABLE, Default: vpntopt
VPNAUTH_SQLALCHEMY_DATABASE_URI, Default: postgresql+psycopg2://vpnauth:vpnauth@127.0.0.1:5432/vpnauth
```

## DynamoDB tables

to use all features, create the dynamodb tables: vpnpasswd, vpntotp, vpnmac

All tables use the Partition key: UserId