from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, TextAreaField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
import random
import base64
import secrets
from datetime import datetime
import subprocess

# Load environment variables
load_dotenv()

db = SQLAlchemy()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "fallback-secret-key-change-in-production")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///video-meeting.db")
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Register, int(user_id))

class Register(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)  # Increased length to store hash
    # Add field for user's encryption key
    public_key = db.Column(db.String(256), nullable=False)
    private_key = db.Column(db.String(256), nullable=False)
    encryption_key = db.Column(db.String(64), nullable=True)
    # Relationship with messages
    messages_sent = db.relationship('SecureMessage', 
                                    foreign_keys='SecureMessage.sender_id',
                                    backref='sender', lazy='dynamic')
    messages_received = db.relationship('SecureMessage', 
                                       foreign_keys='SecureMessage.recipient_id',
                                       backref='recipient', lazy='dynamic')

    def is_active(self):
        return True

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        return True


class SecureMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('register.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('register.id'))
    encrypted_content = db.Column(db.Text, nullable=False)
    encryption_key = db.Column(db.String(64), nullable=False)  # Store RC4 key
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)


with app.app_context():
    db.create_all()


class RegistrationForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()])
    first_name = StringField(label="First Name", validators=[DataRequired()])
    last_name = StringField(label="Last Name", validators=[DataRequired()])
    username = StringField(label="Username", validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8, max=20)])


class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])


class MessageForm(FlaskForm):
    recipient = StringField(label="Username", validators=[DataRequired()])
    message = TextAreaField(label="Message", validators=[DataRequired()])


def xor_public_keys(pub_key_1, pub_key_2):
    # Convert public keys to bytes and XOR them to create a session key
    key_1_bytes = base64.b64decode(pub_key_1)
    key_2_bytes = base64.b64decode(pub_key_2)

    # Ensure both keys are the same length
    if len(key_1_bytes) > len(key_2_bytes):
        key_2_bytes = key_2_bytes.ljust(len(key_1_bytes), b'\0')
    elif len(key_2_bytes) > len(key_1_bytes):
        key_1_bytes = key_1_bytes.ljust(len(key_2_bytes), b'\0')

    # XOR both byte arrays to generate a symmetric encryption key
    session_key = bytearray()
    for i in range(len(key_1_bytes)):
        session_key.append(key_1_bytes[i] ^ key_2_bytes[i])

    # Return the first 16 bytes as the 128-bit session key
    return base64.b64encode(session_key[:16])  # 128-bit key


def rc4(key, data):
    # Initialize state array
    S = list(range(256))
    j = 0
    key_stream = []

    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-random generation algorithm (PRGA)
    i = 0
    j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        key_stream.append(S[(S[i] + S[j]) % 256])

    # XOR plaintext with keystream
    return bytes([byte ^ key_stream[i] for i, byte in enumerate(data)])


# Encryption Function (Use a base64 encoded key)
def encrypt_message_rc4(plaintext, key):
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = base64.b64decode(key)  # Decode the base64 key
    ciphertext = rc4(key_bytes, plaintext_bytes)
    return base64.b64encode(ciphertext).decode('utf-8')


# Decryption Function
def decrypt_message_rc4(ciphertext, key):
    ciphertext_bytes = base64.b64decode(ciphertext)  # Decode the base64 ciphertext
    key_bytes = base64.b64decode(key)  # Decode the base64 key
    decrypted_data = rc4(key_bytes, ciphertext_bytes)
    return decrypted_data.decode('utf-8')

def encrypt_password(password, key):
    result = subprocess.run(['python', 'des.py', password, key], capture_output=True, text=True)
    return result.stdout.strip()

def encrypt_password(password, key):
    result = subprocess.run(['python', 'des.py', password, key], capture_output=True, text=True)
    return result.stdout.strip()


def verify_password(input_password, stored_password, key):
    encrypted_input = encrypt_password(input_password, key)
    return encrypted_input == stored_password

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegistrationForm()
    if request.method == "POST" and form.validate_on_submit():
        # For simplicity, generate a base64-encoded "public key" for the user
        public_key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        private_key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        encryption_key = form.username.data
        encrypted_password = encrypt_password(form.password.data, encryption_key)

        # Save the user data with the public key
        new_user = Register(
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            password=encrypted_password,  # Store the password in plain (you can hash it later)
            public_key=public_key,
            private_key=private_key,
            encryption_key=encryption_key
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Account created Successfully! <br>You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)

@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Register.query.filter_by(email=email).first()
        if user and verify_password(password, user.password, user.encryption_key):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully!", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    # Get count of unread messages
    unread_count = SecureMessage.query.filter_by(recipient_id=current_user.id, read=False).count()
    return render_template("dashboard.html", 
                           first_name=current_user.first_name, 
                           last_name=current_user.last_name,
                           unread_count=unread_count)

@app.route("/get-zego-token")
@login_required
def get_zego_token():
    room_id = request.args.get("roomID", str(random.randint(1000, 9999)))
    user_id = str(current_user.id)
    username = current_user.username
    
    # In a production environment, use a proper SDK to generate the token
    # For now, we're just providing the credentials from environment variables
    return jsonify({
        "appID": int(os.environ.get("ZEGO_APP_ID")),
        "serverSecret": os.environ.get("ZEGO_SERVER_SECRET"),
        "roomID": room_id,
        "userID": user_id,
        "userName": username
    })


@app.route("/meeting")
@login_required
def meeting():
    return render_template("meeting.html", username=current_user.username)


@app.route("/join", methods=["GET", "POST"])
@login_required
def join():
    if request.method == "POST":
        room_id = request.form.get("roomID")
        return redirect(f"/meeting?roomID={room_id}")

    return render_template("join.html")


def generate_random_key():
    return secrets.token_bytes(32) 

@app.route("/send_message", methods=["POST"])
@login_required
def send_message():
    form = MessageForm()
    if form.validate_on_submit():
        recipient_username = form.recipient.data
        message_text = form.message.data

        # Find recipient
        recipient = Register.query.filter_by(username=recipient_username).first()
        if not recipient:
            flash("User not found.", "danger")
            return redirect(url_for("messages"))

        # Generate encryption key by XORing public keys
        encryption_key = xor_public_keys(current_user.public_key, recipient.public_key)

        # Encrypt the message using RC4 and the generated key
        encrypted_content = encrypt_message_rc4(message_text, encryption_key)

        # Store the encrypted message
        message = SecureMessage(
            sender_id=current_user.id,
            recipient_id=recipient.id,
            encrypted_content=encrypted_content,
            encryption_key=encryption_key.decode('utf-8')  # Store the key as base64
        )
        db.session.add(message)
        db.session.commit()
        flash("Message sent successfully!", "success")

    return redirect(url_for("messages"))


@app.route("/messages")
@login_required
def messages():
    form = MessageForm()
    received = SecureMessage.query.filter_by(recipient_id=current_user.id).order_by(SecureMessage.timestamp.desc()).all()

    decrypted_messages = []
    for msg in received:
        try:
            # Decrypt the message using the stored RC4 key
            key = msg.encryption_key
            content = decrypt_message_rc4(msg.encrypted_content, key)

            # Mark as read
            if not msg.read:
                msg.read = True
                db.session.commit()

            decrypted_messages.append({
                'id': msg.id,
                'sender': msg.sender.username,
                'content': content,
                'timestamp': msg.timestamp,
                'read': msg.read
            })
        except Exception as e:
            # Handle decryption errors
            decrypted_messages.append({
                'id': msg.id,
                'sender': msg.sender.username,
                'content': f"[Encryption error: {str(e)}]",
                'timestamp': msg.timestamp,
                'read': msg.read
            })

    return render_template("messages.html", messages=decrypted_messages, form=form)

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == "__main__":
    app.run(debug=True)
