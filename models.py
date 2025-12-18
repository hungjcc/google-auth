from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), unique=True, nullable = False)
    password = db.Column(db.String(200), nullable = True )

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    expenses = db.relationship('Expense', backref='category', lazy=True)
    
class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable = False)
    amount = db.Column(db.Float, nullable = False)
    date = db.Column(db.String(20), nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category_id  = db.Column(db.Integer, db.ForeignKey('category.id'))









