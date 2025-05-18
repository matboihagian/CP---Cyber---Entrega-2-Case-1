# extensions.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# instancia do Limiter, sem app ainda
limiter = Limiter(key_func=get_remote_address)
