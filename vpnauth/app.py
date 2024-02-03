#!/usr/bin/env python
# fake edit to trigger build: 5
from flask import Flask, request, redirect, session, render_template, url_for
from flask_bootstrap import Bootstrap5
from flask_login import LoginManager, current_user, login_user, logout_user, UserMixin, login_required

from flask_wtf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import DateTime, Column, func
from sqlalchemy.orm import Mapped, mapped_column

import pyotp

import requests
import base64
import hashlib
import os
import sys
import secrets
import tempfile
import sh
from PIL import Image
import base64
import io
import string
import random
import json

import bcrypt
import boto3
from botocore.exceptions import ClientError
# from uuid import uuid1

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import base64

import google_auth_oauthlib

# from data import ACTORS
# from db import init_db
# from user import User
from forms import passwordForm

# TODO:
# - configure db credentials as env vars
# - auth against real google account
# - set up real dns

# hardcoded env vars
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
GOOGLE_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo'

# required env vars
if not os.environ.get('VPNAUTH_GSUITE_DOMAIN'):
    sys.exit("Error: VPNAUTH_GSUITE_DOMAIN environment variable is not set")
else:
    VPNAUTH_GSUITE_DOMAIN = os.environ.get('VPNAUTH_GSUITE_DOMAIN')

if not os.environ.get('VPNAUTH_DYNAMODB_ACCESS_KEY'):
    sys.exit("Error: VPNAUTH_DYNAMODB_ACCESS_KEY environment variable is not set")
else:
    DYNAMODB_ACCESS_KEY = os.environ.get('VPNAUTH_DYNAMODB_ACCESS_KEY')

if not os.environ.get('VPNAUTH_DYNAMODB_SECRET_KEY'):
    sys.exit("Error: VPNAUTH_DYNAMODB_SECRET_KEY environment variable is not set")
else:
    DYNAMODB_SECRET_KEY = os.environ.get('VPNAUTH_DYNAMODB_SECRET_KEY')

if not os.environ.get('VPNAUTH_DYNAMODB_REGION'):
    sys.exit("Error: VPNAUTH_DYNAMODB_REGION environment variable is not set")
else:
    DEFAULT_REGION = os.environ.get('VPNAUTH_DYNAMODB_REGION')

if not os.environ.get('VPNAUTH_GOOGLE_CLIENT_ID'):
    sys.exit("Error: VPNAUTH_GOOGLE_CLIENT_ID environment variable is not set")
else:
    CLIENT_ID = os.environ.get('VPNAUTH_GOOGLE_CLIENT_ID')

if not os.environ.get('VPNAUTH_GOOGLE_CLIENT_SECRET'):
    sys.exit("Error: VPNAUTH_GOOGLE_CLIENT_SECRET environment variable is not set")
else:
    CLIENT_SECRET = os.environ.get('VPNAUTH_GOOGLE_CLIENT_SECRET')

# only trigger TOTP flow if this is set
TOTP_ENCRYPTION_KEY = os.environ.get('VPNAUTH_TOTP_ENCRYPTION_KEY')

# vars with defaults
OVPN_BASE_DIR = os.getenv('VPNAUTH_OVPN_BASE_DIR','/app/static/ovpn')
REDIRECT_URI = os.getenv('VPNAUTH_REDIRECT_URI','http://127.0.0.1:5000/oauth2callback')
SCOPE = os.getenv('VPNAUTH_GOOGLE_SCOPE','openid%20email%20profile')
DYNAMODB_PASSWD_TABLE = os.getenv('VPNAUTH_DYNAMODB_PASSWD_TABLE','vpnpasswd')
DYNAMODB_TOTP_TABLE = os.getenv('VPNAUTH_DYNAMODB_TOTP_TABLE','vpntotp')
SQLALCHEMY_DATABASE_URI = os.getenv('VPNAUTH_SQLALCHEMY_DATABASE_URI','postgresql+psycopg2://vpnauth:vpnauth@127.0.0.1:5432/vpnauth')
PBKDF2_ITERATIONS_STR = os.getenv('VPNAUTH_PBKDF2_ITERATIONS','15000')
PBKDF2_ITERATIONS = int(PBKDF2_ITERATIONS_STR)

class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id: Mapped[str] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str] = mapped_column(unique=True)
    profile_pic: Mapped[str]
    site_role: Mapped[str]
    otp_configured: Mapped[bool]
    password_configured: Mapped[bool]
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())

def form_data_to_vars(form):
    '''Collect all form data and generate a dictionary of vars from it.'''
    form_vars = {}
    form_data = list(form.data.keys())
    form_data.remove('csrf_token')
    form_data.remove('submit')
    for i in form_data:
        val_string = f"form.{i}.data"
        val_data = eval(val_string)
        form_vars[i] = val_data
    return form_vars

def generate_password():
    password = ''.join([random.choice(
        string.ascii_letters + string.digits + string.punctuation) for n in range(23)])
    return password

# dynamodb functions
## password functions
def reset_dynamodb_password(username, password=None):
    '''Create or update a vpn user password.'''
    if not password:
        password = generate_password()
    password_encrypt = lambda password: bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    password_hash = password_encrypt(password).decode()
    item_entry = {
        'UserId': username,
        'Password': password_hash,
    }
    try:
        table = boto3.resource('dynamodb', aws_access_key_id=DYNAMODB_ACCESS_KEY, aws_secret_access_key=DYNAMODB_SECRET_KEY, region_name=DEFAULT_REGION).Table(DYNAMODB_PASSWD_TABLE)
        table.put_item(Item=item_entry)
        message = f"Password hash for {username} reset to {password_hash}"
        return {'message': message, 'error': False}
    except ClientError as e:
        return {'message': e, 'error': True}

def delete_dynamodb_user(username):
    '''Delete a vpn user in dynamodb.'''
    try:
        table = boto3.resource('dynamodb').Table(DYNAMODB_PASSWD_TABLE)
        table.delete_item(Key={'UserId': username})
        message = f'User {username} deleted!'
        return {'message': message, 'error': False}
    except ClientError as e:
        return {'message': e, 'error': True}

def list_dynamodb_users():
    '''List all users in dynamodb vpnauth table.'''
    result = ''
    table = boto3.resource('dynamodb').Table(DYNAMODB_PASSWD_TABLE)
    for i in table.scan()['Items']:
        result += f"{i['UserId']}\n"
    return result.strip()

## totp functions
def reset_dynamodb_totp_secret(username, totp_secret):
    '''Create or update the encrypted TOTP shares secret.'''
    item_entry = {
        'UserId': username,
        'Password': totp_secret,
    }
    try:
        table = boto3.resource('dynamodb', aws_access_key_id=DYNAMODB_ACCESS_KEY, aws_secret_access_key=DYNAMODB_SECRET_KEY, region_name=DEFAULT_REGION).Table(DYNAMODB_TOTP_TABLE)
        table.put_item(Item=item_entry)
        message = f"Secret for {username} set to {totp_secret}"
        return {'message': message, 'error': False}
    except ClientError as e:
        return {'message': e, 'error': True}

# crypto section
def base64Encoding(input):
  dataBase64 = base64.b64encode(input)
  dataBase64P = dataBase64.decode("UTF-8")
  return dataBase64P

def base64Decoding(input):
    return base64.decodebytes(input.encode("ascii"))

def generateSalt32Byte():
  return get_random_bytes(32)

def aesCbcPbkdf2EncryptToBase64(password, plaintext):
  passwordBytes = password.encode("ascii")
  salt = generateSalt32Byte()
  # PBKDF2_ITERATIONS = 15000
  encryptionKey = PBKDF2(passwordBytes, salt, 32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
  cipher = AES.new(encryptionKey, AES.MODE_CBC)
  ciphertext = cipher.encrypt(pad(plaintext.encode("ascii"), AES.block_size))
  ivBase64 = base64Encoding(cipher.iv)
  saltBase64 = base64Encoding(salt)
  ciphertextBase64 = base64Encoding(ciphertext)
  return saltBase64 + ":" + ivBase64 + ":" + ciphertextBase64

def get_ovpns():
    '''Get a list of all openvpn configs from static directory.'''
    ovpns = []
    try:
        basedirname = OVPN_BASE_DIR
        for filename in os.listdir(basedirname):
            if filename.endswith('.ovpn'):
                ovpns.append(filename)
    except FileNotFoundError as e:
        return [e, ovpns]
    return [None, ovpns]

app = Flask(__name__, static_folder='static', static_url_path='/static')
# require login for all static files
app.view_functions['static'] = login_required(app.send_static_file)
# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
# initialize the app with the extension
db.init_app(app)
login_manager = LoginManager()
flask_secret = secrets.token_urlsafe(16)
app.secret_key = flask_secret

# Bootstrap-Flask requires this line
bootstrap = Bootstrap5(app)
# Flask-WTF requires this line
csrf = CSRFProtect(app)
# Flask-Login requires this line
login_manager.init_app(app)

with app.app_context():
    db.create_all()

def generate_state():
    state = base64.urlsafe_b64encode(hashlib.sha256(os.urandom(1024)).digest()).decode('utf-8')
    session['state'] = state
    return state

@login_manager.user_loader
def load_user(user_id):
    '''Flask-Login helper to retrieve a user from our db.'''
    return User.query.get(user_id)

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return redirect('/login')
    totp_enabled = True
    if not TOTP_ENCRYPTION_KEY:
        totp_enabled = False
    ovpnlist = get_ovpns()
    message = None
    if ovpnlist[0]:
        message = get_ovpns()[0]
    list_ovpns = False
    if len(ovpnlist[1]) > 0:
        list_ovpns = True
    return render_template('home.html', current_user=current_user, message=message, list_ovpns=list_ovpns, ovpns=get_ovpns()[1], totp_enabled=totp_enabled)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not current_user.is_authenticated:
        return redirect('/login')
    if current_user.site_role != 'admin':
        return render_template('home.html', current_user=current_user, message="You are not authorized to view this page!")
    message = None
    if request.method == 'POST':
        form = request.form
        if form['action'] == 'list_users':
            message = list_dynamodb_users()
        if form['action'] == 'delete_user':
            response = delete_dynamodb_user(form['username'])
            message = response['message']
    user_list = sorted(list_dynamodb_users().split('\n'))
    # db.session.get
    print(type(user_list))
    print(user_list)
    return render_template('admin.html', current_user=current_user, message=message, user_list=user_list)

@app.route('/password', methods=['GET', 'POST'])
def password():
    if not current_user.is_authenticated:
        return redirect('/login')
    form = passwordForm()
    message = None
    if form.validate_on_submit():
        form_vars = form_data_to_vars(form)
        response = reset_dynamodb_password(current_user.email, form_vars['password'])
        app.logger.debug(f"response: {response}")
        if response['error']:
            message = response['message']
            return render_template('password.html', current_user=current_user, form=form, message=message)
        db_data = {
            User.password_configured: True
        }
        db.session.query(User).filter(User.id == current_user.id).update(db_data)
        db.session.commit()
        return render_template('home.html', current_user=current_user, message="Your password has been reset!")
    return render_template('password.html', current_user=current_user, form=form, message=message)

@app.route('/otpauth')
def otpauth():
    if not current_user.is_authenticated:
        return redirect('/login')
    if not TOTP_ENCRYPTION_KEY:
        return render_template('home.html', current_user=current_user, message="Sorry, TOTP is disabled for this site!")
    userinfo = db.session.query(User).filter(User.id == current_user.id).first()
    if userinfo.otp_configured:
        return render_template("otpauth.html", img_data=None, completed=True)
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=True, suffix='.png')
    temp_file_name = temp_file.name
    secret_key = pyotp.random_base32()
    encrypted_secret = aesCbcPbkdf2EncryptToBase64(TOTP_ENCRYPTION_KEY, secret_key)
    response = reset_dynamodb_totp_secret(current_user.email, encrypted_secret)
    if response['error']:
        message = response['message']
        return render_template('home.html', current_user=current_user, message=message)
    # I was originally going to use the python pyotp library to generate the QR code, but it was not working
    # in conjunction with golang so I fell back to writing a basic CLI with the same golang library I was using 
    # for gsuite_auth to handle the OTP generation.
    sh.qrcreator('--filename', temp_file_name, "--secretkey", secret_key, "--username", current_user.email)
    im = Image.open(temp_file_name)
    data = io.BytesIO()
    im.save(data, "PNG")
    encoded_img_data = base64.b64encode(data.getvalue())
    db_data = {
        User.otp_configured: True
    }
    db.session.query(User).filter(User.id == current_user.id).update(db_data)
    db.session.commit()
    return render_template("otpauth.html", img_data=encoded_img_data.decode('utf-8'), completed=False)

@app.route('/login')
def login():
    state = generate_state()
    auth_url = f'{GOOGLE_AUTH_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={SCOPE}&state={state}'
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    if request.args.get('state') != session.get('state'):
        return 'Invalid state', 400
    authorization_code = request.args.get('code')
    token_payload = {
        'code': authorization_code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    token_response = requests.post(GOOGLE_TOKEN_URL, data=token_payload)
    token_data = token_response.json()
    access_token = token_data.get('access_token')
    userinfo_response = requests.get(GOOGLE_USERINFO_URL, headers={'Authorization': f'Bearer {access_token}'})
    userinfo = userinfo_response.json()
    if userinfo.get("verified_email"):
        unique_id = userinfo["id"]
        users_email = userinfo["email"]
        picture = userinfo["picture"]
        users_name = userinfo["name"]
    else:
        return "User email not available or not verified by Google.", 400
    email_suffix = users_email.split('@')[1]
    if email_suffix != VPNAUTH_GSUITE_DOMAIN:
        return f"User email {users_email} not valid for this site!.", 400
    user = User(
        id=unique_id,
        name=users_name,
        email=users_email,
        profile_pic=picture,
        site_role='user',
        otp_configured=False,
        password_configured=False
    )
    if not db.session.get(User, unique_id):
        db.session.add(user)
        db.session.commit()
    # Begin user session by logging the user in
    login_user(user)
    return redirect('/')

@app.route('/logout')
def logout():
    logout_user()
    return render_template('logout.html')

@app.route('/healthz')
def healthz():
    return 'OK'

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run()
