# openvpn_gsuite_auth
An openvpn plugin to support authorization against GSuite and authentication against a dynamodb instance

# installation

## Gsuite credentials
generate credentials and token files by following the instructions at:

https://developers.google.com/admin-sdk/directory/v1/quickstart/go

## dynamodb setup
create a dynamodb table with the attributes: UserId, Password, UserUUID

UserId - the user's full email address

Password - the user's bcrypt hashed password

UserUUID - a non-email based ID, just in case

## dynamodb access

Create a user with read permissions to dynamodb_table and populate the aws_access/secret_keys in gsuite_auth_config.yaml with the keys for that user.

## Plugin setup
compile and copy gsuite_auth to /usr/local/sbin

configure and copy gsuite_auth_config.yaml to /etc/openvpn/

configure your server by adding the line:

auth-user-pass-verify /usr/local/sbin/gsuite_auth via-env

