import os
import sys
from datetime import datetime

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models.database import User
from werkzeug.security import generate_password_hash

def seed_admin():
    with app.app_context():
        db.drop_all()  # Crucial to ensure schema is fresh
        db.create_all()
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin_user = User(
                username="admin",
                email="admin@example.com",
                password_hash=generate_password_hash("admin123"),
                is_admin=True,
                created_at=datetime.utcnow()
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully.")
        else:
            print("Admin user already exists.")

if __name__ == "__main__":
    seed_admin()
