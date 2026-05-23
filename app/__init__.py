import os
import logging
from flask import Flask
from flask_caching import Cache
from config.settings import Config

cache = Cache()

def create_app(config_class=Config):
    # Use absolute path for template and static folders to avoid lookup errors
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(__name__, 
                template_folder=os.path.join(base_dir, 'templates'),
                static_folder=os.path.join(base_dir, 'static'))
    app.config.from_object(config_class)

    # Initialize Extensions
    cache.init_app(app)

    # Setup Logging
    if not os.path.exists(app.config['LOG_DIR']):
        os.makedirs(app.config['LOG_DIR'])
        
    file_handler = logging.FileHandler(os.path.join(app.config['LOG_DIR'], 'phishguard.log'))
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('PhishGuard Startup')

    # Register Blueprints
    from app.routes.main import main_bp
    app.register_blueprint(main_bp)

    return app
