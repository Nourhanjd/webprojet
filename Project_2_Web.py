from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import string
import random




app = Flask(__name__)
app.secret_key = 'merje'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['STATIC_FOLDER'] = 'Static'
app.permanent_session_lifetime= timedelta(minutes=5)
db = SQLAlchemy(app)

#Define the User model 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Captcha generation function
def generate_captcha_text():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=6))


# Then create the tables with the updated schema
with app.app_context():
    db.create_all()

# Add initial users to the database
initial_users = [
    { 'email': "rihammerkbawi07@gmail.com", 'password': "#riham1234", 'first_name': 'Riham', 'last_name': 'AlMerKbawi' },
    { 'email': "jneidnourhane19@gmail.com", 'password': "*nourhane5678", 'first_name': 'Nourhane', 'last_name': 'Jneid' }
]


with app.app_context():
    for user_data in initial_users:
        existing_user = User.query.filter_by(email=user_data['email']).first()
        if not existing_user:
            hashed_password = generate_password_hash(user_data['password'], method='pbkdf2:sha256')
            new_user = User(email=user_data['email'], 
                            first_name=user_data['first_name'], 
                            last_name=user_data['last_name'],
                            password=hashed_password)
            db.session.add(new_user)
            
    # Commit the changes
    db.session.commit()



# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Retrieve user from the database based on the provided email
        user = User.query.filter_by(email=email).first()

        if user:
            # Check if the provided password matches the hashed password stored in the database
            if check_password_hash(user.password, password):
                if user.email == 'rihammerkbawi07@gmail.com' or user.email == 'jneidnourhane19@gmail.com':
                    session['user_first_name'] = 'Admin'
                    # If the email is one of the initialized ones, redirect to the admin panel route
                    return redirect(url_for('admin_panel'))
                else:
                    flash("Logged in successfully")
                    session['user_first_name'] = user.first_name
                    return redirect(url_for('captcha'))
            else:
                flash("Incorrect password. Please try again.", "error")
                return render_template('newINDEXfinal.html')
        else:
            flash("Email not found. Please register.", "error")
            return redirect(url_for('register'))
    else:
        return render_template('newINDEXfinal.html')


# Admin panel route
@app.route('/admin_panel')
def admin_panel():
    # Check if the user is an admin
    if 'user_first_name' in session and session['user_first_name'] == 'Admin':
        # Render the admin panel template
        return render_template('admin_panel.html')
    else:
        # If not an admin, redirect to the login page
        flash("You are not authorized to access this page.", "error")
        return redirect(url_for('login'))


# Users accounts route
@app.route('/users_accounts')
def users_accounts():
    # Check if the user is an admin
    if 'user_first_name' in session and session['user_first_name'] == 'Admin':
        # Retrieve all users from the database
        users = User.query.all()
        # Render the users accounts template and pass the users data to it
        return render_template('users_accounts.html', users=users)
    else:
        # If not an admin, redirect to the login page
        flash("You are not authorized to access this page.", "error")
        return redirect(url_for('login'))

    
#Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if password and confirm password match
        if password != confirm_password:
            flash('Password and confirm password do not match.', 'error')
            return redirect(url_for('register'))

        # Check if the email is already registered
        if User.query.filter_by(email=email).first():
            flash('Email is already registered. Please use a different email.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, first_name=first_name, last_name=last_name, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. You can now log in.', 'success')
        return redirect(url_for('captcha'))

    return render_template('newregisterfinal.html')

@app.route('/captcha', methods=['GET', 'POST'])
def captcha():
    if request.method == 'POST':
        captcha_input = request.form.get('captcha-text')
        captcha_text = session.get('captcha_text')
        
        if captcha_input == captcha_text:
            # Captcha validation successful
            flash("Captcha validation successful")
            return redirect(url_for('demo_web'))
        else:
            # Captcha validation failed
            flash("Invalid captcha. Please try again.", "error")
            return redirect(url_for('captcha'))
        
    # Generate captcha text and store in session
    captcha_text = generate_captcha_text()
    session['captcha_text'] = captcha_text
    
    # Pass flashed messages to the template
    return render_template('newcaptchafinal.html', captcha_text=captcha_text)

@app.route('/demo_Web')
def demo_web():
    # Render the demoWeb.html template
    return render_template('demoWebfinal.html')

#chat route
@app.route('/chat')
def chat():
    # Retrieve user's first name from session
    user_first_name = session.get('user_first_name', 'User')
    
    # Check if the user is an admin
    if user_first_name == 'Admin':
        user_greeting = "Hello, Admin"
    elif user_first_name != 'User':  # Check if the user is not a new user with default name 'User'
        user_greeting = f"Hello, {user_first_name}"
    else:
        user_greeting = "Hello, User"

    return render_template('newchatfinal.html', user_greeting=user_greeting)

@app.route('/logout', methods=['POST'])
def logout():
    # Clear the user session
    session.clear()
    # Redirect the user to the login route
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=False)
