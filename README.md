Projeto: API de Autenticação (Case 1)
Descrição: aplicação Flask para registro e login de usuários via CPF e senha, retornando tokens JWT para acesso a rotas protegidas.

Seções:

Tecnologias – Python 3.12, Flask, Flask-SQLAlchemy, Flask-Limiter, bcrypt, PyJWT, SQLite, pytest.
Estrutura de pastas – app.py, auth.py, config.py, extensions.py, models.py, requirements.txt, README.md.
Instalação e configuração
Clone do repositório
Criação e ativação de venv
pip install -r requirements.txt
Ajuste de chaves em config.py (SECRET_KEY, JWT_SECRET, SQLALCHEMY_DATABASE_URI).
Como executar – comando python app.py e endereço base (http://localhost:5001/).
Descrição dos endpoints
POST /auth/register – cabeçalho Content-Type: application/json; corpo com cpf e password; respostas 201, 400, 409.
POST /auth/login – cabeçalho Content-Type; corpo com cpf e password; respostas 200 com access_token, 401 e 429 (rate limit 5/min).
GET /auth/me – cabeçalho Authorization: Bearer <token>; respostas 200, 401 em token inválido/expirado.
