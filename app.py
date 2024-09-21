from flask import Flask, render_template, url_for, flash, redirect, request, make_response
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from config import Config
from models import db, bcrypt, User, Session, Report
from forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm, RequestActivationForm, ReportUserForm, BlockUserForm
from functools import wraps
from dotenv import load_dotenv
from datetime import datetime, timedelta
import uuid
import math
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
limit = 10

with app.app_context():
    db.drop_all()
    db.create_all()
    username="test"
    password="test"
    email='test@gmail.com'
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, email=email, password=hashed_password, active=True)
    db.session.add(user)
    db.session.commit()

def pagination(clazz, count, rows):
    entries = []
    for row in rows:
        row_dict = row._asdict()
        instance = clazz(**row_dict)
        entries.append(instance)
    page_count = math.ceil(count/limit)
    page_range = range(1, page_count+1)
    return entries, page_count, page_range

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/internal")
@login_required
def internal():
    return render_template('internal.html')

@app.route("/users")
@login_required
def users():
    pagenum = request.args.get('page', default=1, type=int)
    offset = (pagenum-1) * limit
    count = db.session.query(User).count()
    entries = db.session.query(User.username, User.email, User.password, User.active, User.image_file).limit(limit).offset(offset).all()
    users, page_count, page_range = pagination(User, count, entries)
    return render_template('users.html', users=users, page_count=page_count, pagenum=pagenum, page_range=page_range)

@app.route("/sessions/<username>")
@login_required
def sessions(username):
    pagenum = request.args.get('page', default=1, type=int)
    offset = (pagenum-1) * limit
    user = db.session.query(User).filter_by(username=username).first()
    count = db.session.query(Session).filter_by(user_id=user.id).count()
    entries = db.session.query(Session.user_id, Session.token, Session.created_at, Session.expires_at, Session.active, Session.device, Session.ip_address).filter_by(user_id=user.id).limit(limit).offset(offset).all()
    sessions, page_count, page_range = pagination(Session, count, entries)
    return render_template('sessions.html', sessions=sessions, page_count=page_count, pagenum=pagenum, page_range=page_range, username=username)

@app.route("/reports/<username>")
@login_required
def user_reports(username):
    pagenum = request.args.get('page', default=1, type=int)
    offset = (pagenum-1) * limit
    user = db.session.query(User).filter_by(username=username).first()
    count = db.session.query(Report).filter_by(user_id=user.id).count()
    entries = db.session.query(Report.id, Report.user_id, Report.created_at, Report.expires_at, Report.explaination).filter_by(user_id=user.id).limit(limit).offset(offset).all()
    reports, page_count, page_range = pagination(Report, count, entries)
    return render_template('reports.html', reports=reports, page_count=page_count, pagenum=pagenum, page_range=page_range, username=username)

@app.route("/reports")
@login_required
def reports():
    page = db.paginate(db.select(Report), max_per_page=10)
    return render_template("reports.html", page=page)

@app.route("/report_user/<username>", methods=['GET', 'POST'])
@login_required
def report_user(username):
    form = ReportUserForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(username=username).first()
        ## TODO check if user found
        new_report = Report(
            user_reported_id=user.id,
            user_reporting_id=user.id,
            created_at=datetime.utcnow(),
            expires_at=None,
            explaination=form.explaination.data
        )
        db.session.add(new_report)
        db.session.commit()
        flash(f'User {username} has been reported.', 'success')
        return redirect(url_for('report_user', username=username))
    return render_template('report_user.html', title='Report User', username=username, form=form)

@app.route("/block_user/<report_id>", methods=['GET', 'POST'])
@login_required
def block_user(report_id):
    form = BlockUserForm()
    report = db.session.get(Report, int(report_id))
    if form.validate_on_submit():
        report.expires_at = form.date.data
        db.session.commit()
        flash(f'Report has been confirmed, user is now blocked.', 'success')
        return redirect(url_for('reports'))
    return render_template('block_user.html', title='Report User', form=form, report=report)

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
        if user is None:
            flash('Login Unsuccessful. Account does not exist.', 'info')
        elif not user.active:
            flash('Login Unsuccessful. Account is not active, please check your email box or resend activation email.', 'info')
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

if __name__=="__main__":
    app.run(debug=True, host='0.0.0.0', port=8080)
