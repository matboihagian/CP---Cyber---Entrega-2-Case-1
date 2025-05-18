import os

SECRET_KEY = os.getenv('SECRET_KEY', 'troque-esta-chave')
JWT_SECRET = os.getenv('JWT_SECRET', 'troque-esta-chave-jwt')
