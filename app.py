from flask import Flask
from models import db
from auth import auth_bp
from extensions import limiter  # import do limiter configurado em extensions.py

def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')

    # Banco de dados
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    # rate limiting
    limiter.init_app(app)

    # blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # criar tabelas se não existirem
    with app.app_context():
        db.create_all()

    @app.route('/')
    def index():
        return 'API Auth rodando!', 200
    
    return app

if __name__ == '__main__':
    create_app().run(debug=True, port=5001)
