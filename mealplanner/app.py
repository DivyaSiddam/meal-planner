from flask import Flask, render_template, redirect, url_for, flash , request

from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField , SelectField
from wtforms.validators import InputRequired, Length, EqualTo, Email
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import get_flashed_messages
import os

# Initialize Flask App
app = Flask(__name__)

# ✅ Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:12345@localhost:3308/mealplanner_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)  # Generates a random secret key

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ------------------------
# ✅ Database Models (Without Phone Number)
# ------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ingredients = db.Column(db.Text, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    mealplan_id = db.Column(db.Integer, db.ForeignKey('meal_plan.id'), nullable=True)  # ✅ Allow NULL values





class MealPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# ------------------------
# ✅ Forms (Without Phone Number)
# ------------------------
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=120)])
    first_name = StringField('First Name', validators=[InputRequired(), Length(max=50)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class MealPlanForm(FlaskForm):
    name = StringField('Meal Plan Name', validators=[InputRequired()])
    date = DateField('Date', validators=[InputRequired()])
    submit = SubmitField('Create Meal Plan')


class RecipeForm(FlaskForm):
    name = StringField('Recipe Name', validators=[InputRequired()])
    ingredients = TextAreaField('Ingredients', validators=[InputRequired()])
    instructions = TextAreaField('Instructions', validators=[InputRequired()])
    mealplan_id = SelectField('Assign to Meal Plan', coerce=int)  # ✅ Add this field
    submit = SubmitField('Add Recipe')


# ------------------------
# ✅ User Loader for Flask-Login
# ------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------------
# ✅ Routes
# ------------------------
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        existing_email = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            flash('❌ Username already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        if existing_email:
            flash('❌ An account with this email already exists.', 'danger')
            return redirect(url_for('register'))

        # ✅ Hash password before saving
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            password=hashed_password  # ✅ Ensure hashed password is stored
        )

        db.session.add(new_user)
        db.session.commit()

        print(f"✅ User Registered: {form.username.data} - Hashed Password: {hashed_password}")  # Debugging

        flash('✅ Registered successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user:
            print(f"✅ Found user: {user.username}")
            print(f"🔑 Stored Password Hash: {user.password}")  # Debugging stored hash
            print(f"🔐 Entered Password: {form.password.data}")  # Debugging user input
            print(f"🛠 Hash Comparison Result: {bcrypt.check_password_hash(user.password, form.password.data)}")

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('✅ Login Successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('❌ Login Failed. Check username and password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("✅ You have been logged out.", "success")
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    meal_plans = MealPlan.query.filter_by(id=current_user.id).all()
    recipes = Recipe.query.filter_by(id=current_user.id).all()
    messages = get_flashed_messages(with_categories=True)  # ✅ Capture flash messages
    return render_template('dashboard.html', username=current_user.username, meal_plans=meal_plans, recipes=recipes, messages=messages)

@app.route('/grocery_list/<int:mealplan_id>')
@login_required
def grocery_list(mealplan_id):
    mealplan = MealPlan.query.get_or_404(mealplan_id)
    recipes = Recipe.query.filter_by(mealplan_id=mealplan_id).all()

    grocery_items = {}  # ✅ Store ingredients and count occurrences

    if not recipes:
        flash("No recipes found for this meal plan!", "warning")
        return render_template('grocery_list.html', mealplan=mealplan, grocery_items=grocery_items)

    for recipe in recipes:
        if recipe.ingredients:  # ✅ Ensure ingredients exist
            ingredients = recipe.ingredients.split(',')  # ✅ Split comma-separated ingredients
            for ingredient in ingredients:
                ingredient = ingredient.strip().lower()  # ✅ Normalize text
                grocery_items[ingredient] = grocery_items.get(ingredient, 0) + 1

    return render_template('grocery_list.html', mealplan=mealplan, grocery_items=grocery_items)



@app.route('/mealplan/<int:mealplan_id>')
@login_required
def mealplan_detail(mealplan_id):
    mealplan = MealPlan.query.get_or_404(mealplan_id)
    return render_template('mealplan_detail.html', mealplan=mealplan)


# ✅ Add the add_mealplan route HERE (below dashboard)
@app.route('/add_mealplan', methods=['GET', 'POST'])
@login_required
def add_mealplan():
    form = MealPlanForm()
    
    if form.validate_on_submit():
        new_mealplan = MealPlan(
            name=form.name.data,
            date=form.date.data,
            user_id=current_user.id
        )
        db.session.add(new_mealplan)
        db.session.commit()
        
        flash('✅ Meal plan added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_mealplan.html', form=form)

@app.route('/add_recipe', methods=['GET', 'POST'])
@login_required
def add_recipe():
    form = RecipeForm()
    mealplans = MealPlan.query.all()  # Fetch meal plans from the database

    # ✅ Populate the meal plan dropdown
    form.mealplan_id.choices = [(mp.id, mp.name) for mp in mealplans]

    if form.validate_on_submit():
        selected_mealplan_id = form.mealplan_id.data if form.mealplan_id.data else None  # ✅ Ensure it's valid

        new_recipe = Recipe(
            name=form.name.data,
            ingredients=form.ingredients.data,
            instructions=form.instructions.data,
            mealplan_id=selected_mealplan_id  # ✅ Assign mealplan_id properly
        )
        db.session.add(new_recipe)
        db.session.commit()
        flash('Recipe added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_recipe.html', form=form, mealplans=mealplans)


# ------------------------
# ✅ Database Initialization (Ensures Tables Exist)
# ------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
