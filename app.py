import binascii
import hashlib
from urllib.parse import urljoin, urlparse

from flask import Flask, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    fresh_login_required,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField

app =Flask(__name__)
app.config.from_pyfile('config.cfg')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'First, please log in using this form:'
login_manager.refresh_view = 'login'
login_manager.needs_refresh_message = 'You need to log on again'


class User(db.Model, UserMixin):
    # id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(100))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))

    def __repr__(self):
        return ('User:{}, {}'.format(self.name))
    
    def get_id(self):
        return self.name
    

    def get_hash_password(password):
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')
    
    def verify_password(stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'),  100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password
    

@login_manager.user_loader
def load_user(name):
    return User.query.filter(User.name==name).first()

# @login_manager.user_loader
# def load_user(id):
#     return User.query.filter(User.id==id).first()

def is_safe_url(target):
    # target = 'https://www.google.cm/'
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    test_url = urlparse(urljoin(request.host_url, target))
    # print('target: ', target)
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc




class LoginForm(FlaskForm):
    name = StringField('User name')
    password = PasswordField('Password')
    remember = BooleanField('Remember me')


@app.route('/init')
def init():

    db.create_all()

    admin = User.query.filter(User.name=='admin').first()
    if admin == None:
        admin = User(
                    # id=1, 
                    name='admin', password= User.get_hash_password('Passw0rd'),
                            first_name='King',last_name='Kong')
        

        db.session.add(admin)
        db.session.commit()

    return '<h1>Initial configuration done!</h1>'

@app.route('/')
def index():
    return '<h1>Hello<h1>'


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter(User.name ==form.name.data).first()
        if user != None and User.verify_password(user.password, form.password.data):
            # login_user(user)
            login_user(user, remember=form.remember.data)

            next = request.args.get('next')
            # print('next ', next)
            if next and is_safe_url(next):
                return redirect(next)
            else:
                return '<h1>You are authenticated!</h1>'

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return '<h1>You are logged out<h1>'

@app.route('/docs')
@login_required
def docs():
    return '<h1>You have acces to protected docs. You are {}<h1>'.format(current_user.name)

@app.route('/secrets')
@fresh_login_required
def secrets():
    return '<h1>You have acces to protected secrets<h1>'


if __name__ =='__main__':
    app.run()