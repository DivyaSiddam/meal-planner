from app import db, User, app  # Ensure you import `app`

# Fix: Use `app.app_context()`
with app.app_context():
    users = User.query.all()
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}, Password Hash: {user.password}")
