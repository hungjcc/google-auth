from flask import Flask, render_template, redirect, session, url_for, request, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from models import db, User, Expense, Category
from authlib.integrations.flask_client import OAuth
import requests
import os
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    # Use Google's OpenID Connect discovery document so Authlib can obtain jwks_uri
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username = username).first():
            flash('Username already exists!', 'error')
        else:
            new_user = User(username = username, password = password )
            db.session.add(new_user)
            db.session.commit()

            flash('Registration Successful. Please login!', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username = request.form['username']).first()

        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    expenses = Expense.query.filter_by(user_id = current_user.id).all()
    category_totals = {}

    for exp in expenses:
        cat_name = exp.category.name if exp.category else 'Uncategorized'
        category_totals['cat_name'] = category_totals.get(cat_name, 0) + exp.amount

    suggestions = []
    if category_totals:
        max_cat = max(category_totals, key = category_totals.get)
        max_amt = category_totals[max_cat]

        if max_amt > 3000 :
            suggestions.append(f"You spent ${max_amt} on {max_cat}. Consider reducing it.")
        else:
            suggestions.append('Your spending is within healthy limits.')

    return render_template(
        'dashboard.html',
        username = current_user.username,
        expenses = expenses,
        categories = list(category_totals.keys()),
        totals = list(category_totals.values()),
        suggestions = suggestions
    )

@app.route('/add', methods=['GET','POST'])
@login_required
def add_expense():
    categories = Category.query.all()

    if request.method == 'POST':
        title = request.form['title']
        amount = float(request.form['amount'])
        date = request.form['date']
        category_id = request.form['category_id']

        new_expense = Expense(
            title = title,
            amount = amount,
            date = date,
            user_id = current_user.id,
            category_id = category_id
        )

        db.session.add(new_expense)
        db.session.commit()
        flash('Expense added!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_expenses.html', categories = categories)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_expense(id):
    expense = Expense.query.get_or_404(id)
    categories = Category.query.all()

    if expense.user_id != current_user.id:
        flash('Unauthorized access!', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        expense.title = request.form['title']
        expense.amount = float(request.form['amount'])
        expense.date = request.form['date']
        expense.category_id = request.form['category_id']

        db.session.commit()
        flash('Expense updated!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_expenses.html', expense = expense, categories = categories)

@app.route('/delete/<int:id>')
@login_required
def delete_expense(id):
    expense = Expense.query.get_or_404(id)
    if expense.user_id != current_user.id:
        flash('Unauthorized access!', 'error')
        return redirect(url_for('dashboard'))

    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    # Revoke Google token if present, then clear session and logout
    token = session.pop('oauth_token', None)
    if token:
        access_token = token.get('access_token') or token.get('id_token')
        if access_token:
            try:
                # Google's token revocation endpoint accepts POST with form-encoded body
                resp = requests.post(
                    'https://oauth2.googleapis.com/revoke',
                    params={'token': access_token},
                    headers={'content-type': 'application/x-www-form-urlencoded'},
                    timeout=5
                )
                app.logger.debug(f"Google revoke response: {resp.status_code} - {resp.text}")
            except Exception as e:
                app.logger.warning(f"Failed to revoke Google token: {e}")

    logout_user()
    session.pop('username', None)
    # Clear any remaining session items to fully sign out locally
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# Categories CRUD
@app.route('/categories')
@login_required
def list_categories():
    categories = Category.query.all()
    return render_template('categories.html', categories=categories)


@app.route('/categories/add', methods=['GET', 'POST'])
@login_required
def add_category():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        if Category.query.filter_by(name=name).first():
            flash('Category already exists!', 'error')
        else:
            new_cat = Category(name=name, description=description)
            db.session.add(new_cat)
            db.session.commit()
            flash('Category added!', 'success')
            return redirect(url_for('list_categories'))
    return render_template('add_category.html')

@app.route('/categories/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_category(id):
    category = Category.query.get_or_404(id)
    if request.method == 'POST':
        category.name = request.form['name']
        category.description = request.form['description']
        db.session.commit()
        flash('Category updated!', 'success')
        return redirect(url_for('list_categories'))
    return render_template('edit_category.html', category=category)

@app.route('/categories/delete/<int:id>')
@login_required
def delete_category(id):
    category = Category.query.get_or_404(id)
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted!', 'success')
    return redirect(url_for('list_categories'))

@app.route('/login/google')
def login_google():
    try:
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        app.logger.error(f"Error during Google login: {str(e)}") 
        return "Error during Google login", 500
    
@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    userinfo_endpoint = google.server_metadata.get('userinfo_endpoint')
    resp = google.get(userinfo_endpoint)
    user_info = resp.json()
    # You can add logic here to handle the user info, e.g., create a user in your database
    username = user_info['email']
    
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, password=generate_password_hash(os.urandom(16).hex()))
        db.session.add(user)
        db.session.commit()

    # Log the user in via Flask-Login and store oauth info in session
    login_user(user)
    session['username'] = username
    session['oauth_token'] = token
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    with app.app_context():
         db.create_all()
    app.run(debug=True) 



