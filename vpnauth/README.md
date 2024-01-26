# About

vpnauth is a self-service portal for user on-boarding and managing their password and TOTP credentials.

# Installation

## Required environment variables

```VPNAUTH_GSUITE_DOMAIN = os.environ.get('VPNAUTH_GSUITE_DOMAIN')
DYNAMODB_ACCESS_KEY = os.environ.get('VPNAUTH_DYNAMODB_ACCESS_KEY')
DYNAMODB_SECRET_KEY = os.environ.get('VPNAUTH_DYNAMODB_SECRET_KEY')
CLIENT_ID = os.environ.get('VPNAUTH_GOOGLE_CLIENT_ID')
CLIENT_SECRET = os.environ.get('VPNAUTH_GOOGLE_CLIENT_SECRET')
TOPT_ENCRYPTION_KEY = os.environ.get('VPNAUTH_TOPT_ENCRYPTION_KEY')
```

## Override-able environment variables

```REDIRECT_URI = os.getenv('VPNAUTH_REDIRECT_URI','http://127.0.0.1:5000/oauth2callback')
SCOPE = os.getenv('VPNAUTH_GOOGLE_SCOPE','openid%20email%20profile')
DYNAMODB_PASSWD_TABLE = os.getenv('VPNAUTH_DYNAMODB_PASSWD_TABLE','vpnpasswd')
DYNAMODB_TOPT_TABLE = os.getenv('VPNAUTH_DYNAMODB_TOPT_TABLE','vpntopt')
SQLALCHEMY_DATABASE_URI = os.getenv('VPNAUTH_SQLALCHEMY_DATABASE_URI','postgresql+psycopg2://otpserver:otpserver@127.0.0.1:5432/otpserver')
```

