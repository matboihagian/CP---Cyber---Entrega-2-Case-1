from flask import Blueprint, request, jsonify, current_app
from models import db, User
import bcrypt
import jwt
from datetime import datetime, timedelta
import sys
from extensions import limiter 

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    cpf = data.get('cpf')
    pwd = data.get('password')
    if not cpf or not pwd:
        return jsonify({'error': 'cpf e password são obrigatórios'}), 400

    if User.query.filter_by(cpf=cpf).first():
        return jsonify({'error': 'usuário já existe'}), 409

    # gerar hash da senha
    salt = bcrypt.gensalt()
    pwd_hash = bcrypt.hashpw(pwd.encode('utf-8'), salt)

    user = User(cpf=cpf, password_hash=pwd_hash.decode('utf-8'))
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'usuário criado com sucesso'}), 201

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # aplica rate limiting
def login():
    data = request.get_json()
    cpf = data.get('cpf')
    pwd = data.get('password')
    user = User.query.filter_by(cpf=cpf).first()
    if not user or not bcrypt.checkpw(pwd.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'error': 'credenciais inválidas'}), 401

    # criar token JWT
    payload = {
        'sub': str(user.id),  # sub precisa ser string
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm='HS256')
    return jsonify({'access_token': token}), 200

@auth_bp.route('/me', methods=['GET'])
def me():
    auth_header = request.headers.get('Authorization', '')
    # imprime no terminal para depuração
    print(f"Authorization header received: {auth_header}", file=sys.stderr)

    # imprime a chave usada para decodificar
    print(f"Using JWT_SECRET = {current_app.config['JWT_SECRET']!r}", file=sys.stderr)

    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'token não fornecido'}), 401

    token = auth_header.split(' ', 1)[1]
    try:
        data = jwt.decode(token, current_app.config['JWT_SECRET'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'token inválido'}), 401

    user = User.query.get(data['sub'])
    if not user:
        return jsonify({'error': 'usuário não encontrado'}), 404

    return jsonify({'id': user.id, 'cpf': user.cpf}), 200
