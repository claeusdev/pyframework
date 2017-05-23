from flask import Flask, request, render_template, flash, redirect, url_for, session, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)


# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'action06'
app.config['MYSQL_DB'] = 'myblog'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Initialize MySQL
mysql = MySQL(app)

Articles = Articles()

# Home route
@app.route('/')
def index():
    return render_template('home.html')

# About page
@app.route('/about')
def about():
    return render_template('about.html')

# All articles
@app.route('/articles')
def articles():
    return render_template('articles/index.html', articles = Articles)

# Single Article
@app.route('/articles/<string:id>')
def article(id):
    return render_template('articles/show.html', id=id)

#  RegisterForm class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=100)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message= 'Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

# User registers
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        c = mysql.connection.cursor()

        c.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        c.close()

        # Flash Mesaage

        flash('Registered successfully', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html', form = form)

# User Logs in
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields

        username = request.form['username']
        password_candidate = request.form['password']

        # Creating cursor
        c = mysql.connection.cursor()

        # Getting user by username
        result = c.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored encrytpted password
            data = c.fetchone()
            password = data['password']

            # Comparing the Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed password comparison
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')

                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Login'
                return render_template('auth/login.html', error=error)
            c.close()
        else:
            error = "Username not found"
            return render_template('auth/login.html', error=error)

    return render_template('auth/login.html')

# Check is user logged in

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorised!! Please login to continue', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully!', 'success')

    return redirect(url_for('login'))
# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('user/dashboard.html')



if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug = True)
