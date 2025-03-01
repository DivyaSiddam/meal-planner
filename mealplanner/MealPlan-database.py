from app import app  # Import your Flask app instance
from app import db, MealPlan  # Import your database models

with app.app_context():
    mealplans = MealPlan.query.all()
    print(mealplans)  # This should return a list of meal plans
