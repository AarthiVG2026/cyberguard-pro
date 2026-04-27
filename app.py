import os
import logging
from dotenv import load_dotenv
load_dotenv()

from flask import Flask
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix

# extensions are now in core.extensions
from core.extensions import db

# Logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # Secret key
    app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # MySQL (XAMPP) Connection String
    db_uri = os.environ.get(
        "DATABASE_URL",
        "mysql+pymysql://root:@localhost/cyberguardpro"
    )
    app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

    # Init extensions with the app
    db.init_app(app)
    login_manager.init_app(app)
    # login_view must match the endpoint name (web.login)
    login_manager.login_view = 'web.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    # Register blueprints
    from controllers.web_routes import web_bp
    app.register_blueprint(web_bp)

    return app

# Create app instance
app = create_app()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from models.database import User
    return User.query.get(int(user_id))

# Create database tables
with app.app_context():
    try:
        db.create_all()
        logger.info("✅ Database tables created successfully")
    except Exception as e:
        logger.warning(f"⚠️  MySQL unavailable — DB tables skipped: {e}")
        logger.warning("    → Login/history features require MySQL (XAMPP). AI Scanner works without it.")

