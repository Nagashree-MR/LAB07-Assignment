from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '!@#$%^&*()_+='
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index07.html')

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('sign_up'))

        if (len(password) < 8 or
            not re.search(r'[a-z]', password) or
            not re.search(r'[A-Z]', password) or
            not re.search(r'\d$', password)):
            flash('Password does not meet the requirements', 'danger')
            return redirect(url_for('sign_up'))

        hashed_password = generate_password_hash(password)
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('thank_you'))
    
    return render_template('sign_up07.html')

@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('secret_page'))
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('sign_in07.html')

@app.route('/secret_page')
def secret_page():
    if 'user_id' not in session:
        return redirect(url_for('sign_in'))
    
    return render_template('secret_page07.html')

@app.route('/thank_you')
def thank_you():
    return render_template('thank_you07.html')

if __name__ == '__main__':
    app.run(debug=True)
