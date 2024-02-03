# openvpn_gsuite_auth
An openvpn plugin to support authorization against GSuite and authentication against a dynamodb instance

# Installation

copy gsuite_auth_config.yaml-example to gsuite_auth_config.yaml and configure

## Configuration

### Required configuration (password authentication)
The base configuration will allow verification against a bcrypted hash of a password stored in dynamoDB:

```
aws_access_key: an AWS access key with access to dynamodb_table below
aws_secret_key: an AWS secret key with access to dynamodb_table below
aws_region: the AWS region your dynamoDB table lives in
dynamodb_table: your dynamoDB password table, as defined below
```
### GSuite authorization
Setting gsuite_credentials will trigger a check against Gsuite

```
gsuite_credentials: the credentials file as generated in the Gsuite credentials section below
gsuite_token: the token file as generated in the Gsuite credentials section below
optional:
gsuite_org_unit: a Gsuite org unit allowed to connect to this endpoint
```

### MAC address verification
Setting dynamodb_mac_table will trigger a check of the MAC address

```
dynamodb_mac_table: your dynamoDB MAC address table, as defined below 
```


### TOTP authentication
Setting dynamodb_totp_table will trigger a check of the TOTP code

```
dynamodb_totp_table: Your dynamoDB TOTP address table, as defined below
totp_secret: the decryption key for decrypting entries from the table above
```

## Gsuite credentials
generate credentials and token files by following the instructions at:

https://developers.google.com/admin-sdk/directory/v1/quickstart/python

Once you've run the quickstart project, copy the (credentials/token).json files into /etc/openvpn

NOTE: I wasn't able to generate a token with the go example but was able to with python

## dynamodb setup

### password table
create a dynamodb table with the attributes:

```
UserId - the user's full email address
Password - the user's bcrypt hashed password
```

### MAC address table
create a dynamodb table with the attributes:

```
UserId - the user's full email address
MACS - a list of MAC addresses, RE: {"00:00:00:e0:00:0b"}
```

### TOTP password table
create a dynamodb table with the attributes:

```
UserId - the user's full email address
Password - encrypted (AES+CBC+Pbkdf2) password used to generate and verify TOTP
```

## dynamodb access

Create a user with read permissions to dynamodb_table and populate the aws_access/secret_keys in gsuite_auth_config.yaml with the keys for that user.

## Plugin setup

copy the latest release of gsuite_auth to /usr/local/sbin

configure and copy gsuite_auth_config.yaml to /etc/openvpn/

configure your server by adding the lines:

```
script-security 3
auth-user-pass-verify /usr/local/sbin/gsuite_auth via-env
```

# VPNAuth - management interface
VPNAuth is a basic interface designed to allow self-service of passwords and TOTP credentials. It uses google authorization as it's access method. It's available as a docker container. See the vpnauth folder for more information.

# qrcreator
I was originally going to use the python pyotp library to generate the QR code, but it was not working in conjunction with golang so I fell back to writing a basic CLI with the same golang library I used for gsuite_auth to handle the OTP generation.

```
qrcreator --filename [output file] --secretkey [secret used for TOTP generation] --username [userID from TOTP DB]
```