from flask import Flask, render_template, url_for, flash, redirect, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from config import Config
from models import db, bcrypt, User, Session 
from forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm, RequestActivationForm
from functools import wraps
from dotenv import load_dotenv
from datetime import datetime, timedelta
import uuid

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/internal")
@login_required
def internal():
    return render_template('internal.html')

@login_manager.user_loader
def load_user(user_id):
    token = request.cookies.get(Config.COOKIE_NAME)
    if token:
        session = Session.query.filter_by(token=token, active=True).first()
        if session and session.is_valid():
            user = User.query.filter_by(id=session.user_id).first()
            return user
    return None

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        send_activation_email(user)
        flash('Your account has been created! Check your email for activation link.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(username=form.username.data).first()
        if not user.active:
            flash('Login Unsuccessful. Account is not active, please check your email box or resend activation email', 'info')
        else:
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                token = str(uuid.uuid4())
                device_info = request.headers.get('User-Agent')
                ip_address=request.remote_addr

                ## There should be never situation where there are two active sessions!
                db.session.query(Session).filter((Session.device == device_info) & (Session.ip_address == ip_address)).update({'active': False})
                db.session.commit()

                new_session = Session(
                    user_id=user.id,
                    token=token,
                    device=device_info,
                    ip_address=ip_address,
                    created_at=datetime.utcnow(),
                    expires_at=None
                )

                db.session.add(new_session)
                db.session.commit()
                login_user(user, remember=form.remember.data, duration=timedelta(minutes=30))
                response = make_response(redirect(url_for('internal')))
                response.set_cookie(Config.COOKIE_NAME, token, httponly=True, secure=True)
                return response
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
@login_required
def logout():
    token = request.cookies.get(Config.COOKIE_NAME)
    if token:
        session = Session.query.filter_by(token=token).first()
        if session:
            session.active = False
            db.session.commit()
    logout_user()
    response = make_response(redirect(url_for('index')))
    response.delete_cookie(Config.COOKIE_NAME)
    return response

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('request_reset.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='Reset Password', form=form)

@app.route("/request_activation", methods=['GET', 'POST'])
def request_activation():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RequestActivationForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(email=form.email.data).first()
        if user.active:
            flash('The account is already active.', 'info')
        else:
            send_activation_email(user)
            flash('An email has been sent with instructions to activate your account.', 'info')
        return redirect(url_for('login'))
    return render_template('request_activation.html', title='Request Activation', form=form)

@app.route("/resend_activation/<token>", methods=['GET', 'POST'])
def resend_activation(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_activation_token(token)
    if user is None:
        flash('That is an invalid or expired activation token', 'warning')
        return redirect(url_for('request_activation'))
    else:
        user.active = True
        db.session.commit()
        flash('Your account has been activated! You are now able to log in', 'success')
        return redirect(url_for('login'))

def send_reset_email(user):
    token = user.create_reset_token()
    url = url_for('reset_token', token=token, _external=True)
    msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[user.email])
    msg.html = f'''
                To reset your password, visit the following link:<br>
                <a href="{url}">{url}</a><br><br>
                If you did not make this request then simply ignore this email and no changes will be made.
                '''
    mail.send(msg)

def send_activation_email(user):
    token = user.create_activation_token()
    url = url_for('resend_activation', token=token, _external=True)
    msg = Message('Account Activation Request', sender='noreply@demo.com', recipients=[user.email])
    msg.html = f'''
                To activate your account, visit the following link:<br>
                <a href="{url}">{url}</a><br><br>
                If you did not make this request then simply ignore this email and no changes will be made.
                '''
    mail.send(msg)

if __name__ == '__main__':
    app.run(debug=True)
