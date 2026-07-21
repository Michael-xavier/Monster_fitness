"""
Monster Fitness — Backend Flask
Segurança: bcrypt, JWT com JTI, CSRF, rate limiting, security headers,
           audit logs, HSTS, validação robusta, least privilege, sem stack trace em prod.
Conformidade: OWASP Top 10, guia segurança vibe coding.
"""

import os
import re
import secrets
import logging
import logging.handlers
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
import bcrypt
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, make_response, g)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import mysql.connector
from mysql.connector import Error as MySQLError

# ─── CONFIG ───────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY']       = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET']       = os.environ.get('JWT_SECRET',  secrets.token_hex(32))
app.config['JWT_EXPIRY_HOURS'] = int(os.environ.get('JWT_EXPIRY_HOURS', 8))
IS_PROD = os.environ.get('FLASK_ENV', 'production') != 'development'

DB_CONFIG = {
    'host':       os.environ.get('DB_HOST', 'db'),
    'port':       int(os.environ.get('DB_PORT', 3306)),
    'database':   os.environ.get('DB_NAME', 'monsterfitness'),
    'user':       os.environ.get('DB_USER', 'mf_user'),
    'password':   os.environ.get('DB_PASSWORD', 'mf_secret_2025'),
    'charset':    'utf8mb4',
    'autocommit': False,
}

# ─── LOGGING DE AUDITORIA ─────────────────────────────────────────────────────
os.makedirs('/var/log/monsterfitness', exist_ok=True)

# Logger de aplicação geral
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

# Logger de auditoria de segurança (arquivo dedicado)
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
try:
    audit_handler = logging.handlers.RotatingFileHandler(
        '/var/log/monsterfitness/audit.log',
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5
    )
    audit_handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s'
    ))
    audit_logger.addHandler(audit_handler)
except Exception:
    audit_logger.addHandler(logging.StreamHandler())  # fallback para stdout

def audit(event: str, user_id=None, ip=None, extra: dict = None):
    """Registra evento de segurança no log de auditoria."""
    ip = ip or request.remote_addr
    uid = user_id or getattr(g, 'user_id', None)
    msg = f"event={event} | user_id={uid} | ip={ip}"
    if extra:
        msg += " | " + " | ".join(f"{k}={v}" for k, v in extra.items())
    audit_logger.info(msg)

# ─── RATE LIMITING ────────────────────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

# ─── BANCO DE DADOS ───────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        try:
            g.db = mysql.connector.connect(**DB_CONFIG)
        except MySQLError as e:
            log.error("DB connection failed: %s", e)
            g.db = None
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db and db.is_connected():
        db.close()

def init_db():
    """Cria tabelas se não existirem (inclui logs de auditoria)."""
    ddl = """
    CREATE TABLE IF NOT EXISTS usuarios (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        nome          VARCHAR(120)  NOT NULL,
        email         VARCHAR(180)  NOT NULL UNIQUE,
        cpf           VARCHAR(14)   NOT NULL UNIQUE,
        nascimento    DATE,
        telefone      VARCHAR(20),
        senha_hash    VARCHAR(255)  NOT NULL,
        plano         ENUM('mensal','trimestral','semestral','anual','premium') NOT NULL DEFAULT 'mensal',
        objetivo      VARCHAR(30),
        nivel         VARCHAR(20),
        ativo         TINYINT(1)    NOT NULL DEFAULT 1,
        tentativas_login INT NOT NULL DEFAULT 0,
        bloqueado_ate DATETIME,
        criado_em     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
        atualizado_em DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_ativo (ativo)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

    CREATE TABLE IF NOT EXISTS sessoes (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        usuario_id  INT         NOT NULL,
        jti         VARCHAR(64) NOT NULL UNIQUE,
        criado_em   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expira_em   DATETIME    NOT NULL,
        revogado    TINYINT(1)  NOT NULL DEFAULT 0,
        ip_origem   VARCHAR(45),
        user_agent  VARCHAR(255),
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
        INDEX idx_jti (jti),
        INDEX idx_revogado (revogado)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS csrf_tokens (
        token       VARCHAR(64) PRIMARY KEY,
        criado_em   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        usado       TINYINT(1)  NOT NULL DEFAULT 0,
        INDEX idx_criado (criado_em)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS audit_logs (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        usuario_id  INT,
        evento      VARCHAR(100) NOT NULL,
        ip          VARCHAR(45),
        user_agent  VARCHAR(255),
        detalhes    TEXT,
        criado_em   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_evento (evento),
        INDEX idx_usuario (usuario_id),
        INDEX idx_criado (criado_em)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    try:
        db = mysql.connector.connect(**DB_CONFIG)
        cur = db.cursor()
        for stmt in ddl.strip().split(';'):
            stmt = stmt.strip()
            if stmt:
                cur.execute(stmt)
        db.commit()
        cur.close()
        db.close()
        log.info("Database initialized.")
    except MySQLError as e:
        log.error("init_db error: %s", e)

def db_audit(evento: str, user_id=None, detalhes: str = None):
    """Grava evento de auditoria no banco de dados."""
    try:
        db = get_db()
        if not db:
            return
        cur = db.cursor()
        cur.execute(
            "INSERT INTO audit_logs (usuario_id, evento, ip, user_agent, detalhes) VALUES (%s,%s,%s,%s,%s)",
            (
                user_id or getattr(g, 'user_id', None),
                evento,
                request.remote_addr,
                request.headers.get('User-Agent', '')[:255],
                detalhes
            )
        )
        db.commit()
        cur.close()
    except Exception:
        pass  # audit nunca deve derrubar a req principal

# ─── HELPERS JWT ──────────────────────────────────────────────────────────────
def gerar_token(user_id: int) -> str:
    jti = secrets.token_hex(16)
    exp = datetime.now(timezone.utc) + timedelta(hours=app.config['JWT_EXPIRY_HOURS'])
    payload = {'sub': user_id, 'jti': jti, 'exp': exp}

    db = get_db()
    if db:
        cur = db.cursor()
        cur.execute(
            "INSERT INTO sessoes (usuario_id, jti, expira_em, ip_origem, user_agent) VALUES (%s,%s,%s,%s,%s)",
            (
                user_id, jti,
                exp.replace(tzinfo=None),
                request.remote_addr,
                request.headers.get('User-Agent', '')[:255]
            )
        )
        db.commit()
        cur.close()

    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')


def verificar_token(token: str):
    """Usa jwt.verify (decode com secret) — nunca jwt.decode sem verificação."""
    try:
        # jwt.decode COM secret = verificação de assinatura criptográfica
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None, 'Token expirado'
    except jwt.InvalidTokenError:
        return None, 'Token inválido'

    db = get_db()
    if db:
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT revogado FROM sessoes WHERE jti=%s AND usuario_id=%s",
            (payload['jti'], payload['sub'])
        )
        sessao = cur.fetchone()
        cur.close()
        if not sessao or sessao['revogado']:
            return None, 'Sessão encerrada'

    return payload, None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('mf_token')
        if not token:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Não autenticado'}), 401
            return redirect(url_for('login_page'))
        payload, err = verificar_token(token)
        if err:
            if request.path.startswith('/api/'):
                return jsonify({'message': err}), 401
            return redirect(url_for('login_page'))
        g.user_id = payload['sub']
        g.jti = payload['jti']
        return f(*args, **kwargs)
    return decorated

# ─── CSRF ─────────────────────────────────────────────────────────────────────
def gerar_csrf() -> str:
    token = secrets.token_hex(32)
    db = get_db()
    if db:
        cur = db.cursor()
        cur.execute("INSERT INTO csrf_tokens (token) VALUES (%s)", (token,))
        cur.execute("DELETE FROM csrf_tokens WHERE criado_em < NOW() - INTERVAL 2 HOUR")
        db.commit()
        cur.close()
    return token


def validar_csrf(token: str) -> bool:
    if not token:
        return False
    db = get_db()
    if not db:
        return True
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT usado FROM csrf_tokens WHERE token=%s", (token,))
    row = cur.fetchone()
    if row and not row['usado']:
        cur.execute("UPDATE csrf_tokens SET usado=1 WHERE token=%s", (token,))
        db.commit()
        cur.close()
        return True
    cur.close()
    return False

# ─── SEGURANÇA — HEADERS COMPLETOS ────────────────────────────────────────────
@app.after_request
def security_headers(resp):
    # Previne MIME sniffing
    resp.headers['X-Content-Type-Options']  = 'nosniff'
    # Previne clickjacking
    resp.headers['X-Frame-Options']          = 'DENY'
    # XSS legacy protection
    resp.headers['X-XSS-Protection']         = '1; mode=block'
    # Controla informações de referência
    resp.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    # Restringe APIs do browser
    resp.headers['Permissions-Policy']        = 'geolocation=(), microphone=(), camera=()'
    # HSTS — força HTTPS por 1 ano (ativar quando HTTPS estiver configurado)
    if IS_PROD:
        resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    # Content Security Policy
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; "
        "font-src fonts.gstatic.com cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    # Remove cabeçalho que revela tecnologia
    resp.headers.pop('Server', None)
    return resp

# ─── VALIDAÇÃO ROBUSTA ────────────────────────────────────────────────────────
EMAIL_RE  = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
# Senha: mínimo 8 chars, ao menos 1 maiúscula, 1 número, 1 especial
SENHA_RE  = re.compile(r'^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$')
PLANOS_OK = ('mensal', 'trimestral', 'semestral', 'anual', 'premium')
OBJS_OK   = ('hipertrofia', 'emagrecimento', 'condicionamento', 'forca', 'saude', 'funcional')
NIVEIS_OK = ('iniciante', 'intermediario', 'avancado')

def validar_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email or '')) and len(email) <= 180

def validar_cpf(cpf: str) -> bool:
    """Validação matemática completa de CPF."""
    c = re.sub(r'\D', '', cpf or '')
    if len(c) != 11 or len(set(c)) == 1:
        return False
    # Dígito verificador 1
    soma = sum(int(c[i]) * (10 - i) for i in range(9))
    d1 = 11 - (soma % 11)
    d1 = 0 if d1 >= 10 else d1
    if d1 != int(c[9]):
        return False
    # Dígito verificador 2
    soma = sum(int(c[i]) * (11 - i) for i in range(10))
    d2 = 11 - (soma % 11)
    d2 = 0 if d2 >= 10 else d2
    return d2 == int(c[10])

def validar_senha(senha: str) -> tuple[bool, str]:
    """Retorna (válido, mensagem de erro)."""
    if not senha or len(senha) < 8:
        return False, 'Senha deve ter pelo menos 8 caracteres.'
    if not SENHA_RE.match(senha):
        return False, 'Senha deve ter ao menos 1 maiúscula, 1 número e 1 caractere especial.'
    return True, ''

def sanitizar(val: str, max_len: int = 200) -> str:
    if not val:
        return ''
    # Remove caracteres de controle
    val = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(val))
    return val.strip()[:max_len]

# ─── BRUTE FORCE PROTECTION (bloqueio progressivo) ────────────────────────────
MAX_TENTATIVAS = 5
BLOQUEIO_MINUTOS = 15

def verificar_bloqueio(user: dict) -> bool:
    """Retorna True se a conta está bloqueada."""
    if user.get('bloqueado_ate'):
        bloqueado_ate = user['bloqueado_ate']
        if isinstance(bloqueado_ate, str):
            bloqueado_ate = datetime.fromisoformat(bloqueado_ate)
        if bloqueado_ate > datetime.now():
            return True
        # Bloqueio expirou — resetar
        _resetar_tentativas(user['id'])
    return False

def _registrar_tentativa_falha(user_id: int):
    db = get_db()
    if not db:
        return
    cur = db.cursor()
    cur.execute(
        "UPDATE usuarios SET tentativas_login = tentativas_login + 1 WHERE id = %s",
        (user_id,)
    )
    cur.execute("SELECT tentativas_login FROM usuarios WHERE id = %s", (user_id,))
    row = cur.fetchone()
    if row and row[0] >= MAX_TENTATIVAS:
        bloqueio = datetime.now() + timedelta(minutes=BLOQUEIO_MINUTOS)
        cur.execute("UPDATE usuarios SET bloqueado_ate = %s WHERE id = %s", (bloqueio, user_id))
        audit(f"CONTA_BLOQUEADA tentativas={row[0]}", user_id=user_id)
    db.commit()
    cur.close()

def _resetar_tentativas(user_id: int):
    db = get_db()
    if not db:
        return
    cur = db.cursor()
    cur.execute(
        "UPDATE usuarios SET tentativas_login = 0, bloqueado_ate = NULL WHERE id = %s",
        (user_id,)
    )
    db.commit()
    cur.close()

# ─── PÁGINAS ──────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/cadastro')
def cadastro_page():
    return render_template('cadastro.html')

@app.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/matricula')
@login_required
def matricula_page():
    return render_template('matricula.html')

# ─── API: CSRF TOKEN ──────────────────────────────────────────────────────────
@app.route('/api/csrf-token')
def api_csrf_token():
    token = gerar_csrf()
    return jsonify({'token': token})

# ─── API: CADASTRO ────────────────────────────────────────────────────────────
@app.route('/api/cadastro', methods=['POST'])
@limiter.limit("10 per hour")
def api_cadastro():
    csrf = request.headers.get('X-CSRF-Token', '')
    if not validar_csrf(csrf):
        audit("CSRF_INVALIDO rota=/api/cadastro")
        return jsonify({'success': False, 'message': 'Token de segurança inválido.'}), 403

    data = request.get_json(silent=True) or {}

    # Whitelist de campos — sem mass assignment
    nome       = sanitizar(data.get('nome', ''), 120)
    email      = sanitizar(data.get('email', ''), 180).lower()
    cpf        = sanitizar(data.get('cpf', ''), 14)
    nascimento = sanitizar(data.get('nascimento', ''), 10)
    telefone   = sanitizar(data.get('telefone', ''), 20)
    password   = data.get('password', '')
    plano      = sanitizar(data.get('plano', 'mensal'), 20)
    objetivo   = sanitizar(data.get('objetivo', ''), 30)
    nivel      = sanitizar(data.get('nivel', ''), 20)

    # Validações
    if not nome or len(nome) < 2:
        return jsonify({'success': False, 'message': 'Nome inválido.'}), 400
    if not validar_email(email):
        return jsonify({'success': False, 'message': 'E-mail inválido.'}), 400
    if not validar_cpf(cpf):
        return jsonify({'success': False, 'message': 'CPF inválido.'}), 400

    ok_senha, msg_senha = validar_senha(password)
    if not ok_senha:
        return jsonify({'success': False, 'message': msg_senha}), 400

    # Whitelist de enums — previne injeção de valores arbitrários
    if plano not in PLANOS_OK:
        plano = 'mensal'
    if objetivo not in OBJS_OK:
        objetivo = 'saude'
    if nivel not in NIVEIS_OK:
        nivel = 'iniciante'

    # Hash da senha com bcrypt rounds=12
    senha_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

    db = get_db()
    if not db:
        return jsonify({'success': False, 'message': 'Serviço indisponível. Tente novamente.'}), 503

    try:
        cur = db.cursor()
        cur.execute(
            """INSERT INTO usuarios (nome,email,cpf,nascimento,telefone,senha_hash,plano,objetivo,nivel)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (nome, email, cpf, nascimento or None, telefone, senha_hash, plano, objetivo, nivel)
        )
        db.commit()
        user_id = cur.lastrowid
        cur.close()
    except MySQLError as e:
        db.rollback()
        if e.errno == 1062:
            field = 'E-mail' if 'email' in str(e) else 'CPF'
            return jsonify({'success': False, 'message': f'{field} já cadastrado.'}), 409
        log.error("Cadastro DB error: %s", e)
        return jsonify({'success': False, 'message': 'Erro interno. Tente novamente.'}), 500

    audit("CADASTRO_OK", user_id=user_id)
    db_audit("CADASTRO_OK", user_id=user_id)

    token = gerar_token(user_id)
    resp = make_response(jsonify({'success': True, 'message': 'Conta criada com sucesso.'}))
    resp.set_cookie(
        'mf_token', token,
        httponly=True,
        secure=IS_PROD,        # True em produção (HTTPS)
        samesite='Lax',
        max_age=3600 * app.config['JWT_EXPIRY_HOURS']
    )
    return resp, 201

# ─── API: LOGIN ───────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
@limiter.limit("20 per hour")
def api_login():
    csrf = request.headers.get('X-CSRF-Token', '')
    if not validar_csrf(csrf):
        audit("CSRF_INVALIDO rota=/api/login")
        return jsonify({'success': False, 'message': 'Token de segurança inválido.'}), 403

    data = request.get_json(silent=True) or {}
    email    = sanitizar(data.get('email', ''), 180).lower()
    password = data.get('password', '')

    if not validar_email(email) or not password:
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

    db = get_db()
    if not db:
        return jsonify({'success': False, 'message': 'Serviço indisponível.'}), 503

    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT id, senha_hash, ativo, tentativas_login, bloqueado_ate FROM usuarios WHERE email=%s",
        (email,)
    )
    user = cur.fetchone()
    cur.close()

    # Resposta genérica — não revela se o e-mail existe
    if not user or not user['ativo']:
        audit(f"LOGIN_FALHA_USUARIO_NAO_ENCONTRADO email={email}")
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

    # Verificar bloqueio por força bruta
    if verificar_bloqueio(user):
        audit("LOGIN_BLOQUEADO", user_id=user['id'])
        return jsonify({'success': False, 'message': f'Conta bloqueada. Tente novamente em {BLOQUEIO_MINUTOS} minutos.'}), 429

    if not bcrypt.checkpw(password.encode('utf-8'), user['senha_hash'].encode('utf-8')):
        _registrar_tentativa_falha(user['id'])
        db_audit("LOGIN_FALHA_SENHA", user_id=user['id'])
        audit("LOGIN_FALHA_SENHA", user_id=user['id'])
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

    # Login bem-sucedido
    _resetar_tentativas(user['id'])
    audit("LOGIN_OK", user_id=user['id'])
    db_audit("LOGIN_OK", user_id=user['id'])

    token = gerar_token(user['id'])
    resp = make_response(jsonify({'success': True, 'message': 'Login realizado.'}))
    resp.set_cookie(
        'mf_token', token,
        httponly=True,
        secure=IS_PROD,
        samesite='Lax',
        max_age=3600 * app.config['JWT_EXPIRY_HOURS']
    )
    return resp

# ─── API: ME (dados do usuário logado) ────────────────────────────────────────
@app.route('/api/me')
@login_required
def api_me():
    db = get_db()
    if not db:
        return jsonify({'message': 'Serviço indisponível.'}), 503

    cur = db.cursor(dictionary=True)
    # Menor exposição de dados — sem senha_hash, sem campos internos
    cur.execute(
        "SELECT id, nome, email, plano, objetivo, nivel, criado_em FROM usuarios WHERE id=%s AND ativo=1",
        (g.user_id,)
    )
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'message': 'Usuário não encontrado.'}), 404

    if user.get('criado_em'):
        user['criado_em'] = user['criado_em'].isoformat()

    return jsonify({'user': user})

# ─── API: ATUALIZAR PERFIL ────────────────────────────────────────────────────
@app.route('/api/me/update', methods=['PUT'])
@login_required
@limiter.limit("30 per hour")
def api_update_me():
    csrf = request.headers.get('X-CSRF-Token', '')
    if not validar_csrf(csrf):
        audit("CSRF_INVALIDO rota=/api/me/update")
        return jsonify({'success': False, 'message': 'Token de segurança inválido.'}), 403

    data = request.get_json(silent=True) or {}

    # Whitelist explícita de campos atualizáveis — sem mass assignment
    nome     = sanitizar(data.get('nome', ''), 120)
    email    = sanitizar(data.get('email', ''), 180).lower()
    telefone = sanitizar(data.get('telefone', ''), 20)
    objetivo = sanitizar(data.get('objetivo', ''), 30)
    plano    = sanitizar(data.get('plano', ''), 20)

    if not nome or len(nome) < 2:
        return jsonify({'success': False, 'message': 'Nome inválido.'}), 400
    if not validar_email(email):
        return jsonify({'success': False, 'message': 'E-mail inválido.'}), 400
    if plano not in PLANOS_OK:
        return jsonify({'success': False, 'message': 'Plano inválido.'}), 400
    if objetivo and objetivo not in OBJS_OK:
        return jsonify({'success': False, 'message': 'Objetivo inválido.'}), 400

    db = get_db()
    if not db:
        return jsonify({'success': False, 'message': 'Serviço indisponível.'}), 503

    try:
        cur = db.cursor()
        cur.execute(
            "UPDATE usuarios SET nome=%s, email=%s, telefone=%s, objetivo=%s, plano=%s WHERE id=%s",
            (nome, email, telefone, objetivo, plano, g.user_id)
        )
        db.commit()
        cur.close()
        audit("PERFIL_ATUALIZADO")
        db_audit("PERFIL_ATUALIZADO")
        return jsonify({'success': True, 'message': 'Perfil atualizado.'})
    except MySQLError as e:
        db.rollback()
        if e.errno == 1062:
            return jsonify({'success': False, 'message': 'E-mail já em uso.'}), 409
        log.error("Update error: %s", e)
        return jsonify({'success': False, 'message': 'Erro interno.'}), 500

# ─── API: LOGOUT ──────────────────────────────────────────────────────────────
@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    db = get_db()
    if db:
        cur = db.cursor()
        cur.execute("UPDATE sessoes SET revogado=1 WHERE jti=%s", (g.jti,))
        db.commit()
        cur.close()

    audit("LOGOUT_OK")
    db_audit("LOGOUT_OK")

    resp = make_response(jsonify({'success': True}))
    resp.delete_cookie('mf_token')
    return resp

# ─── API: DELETE ACCOUNT ──────────────────────────────────────────────────────
@app.route('/api/delete-account', methods=['DELETE'])
@login_required
@limiter.limit("5 per hour")
def api_delete_account():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    db = get_db()
    if not db:
        return jsonify({'success': False, 'message': 'Serviço indisponível.'}), 503

    cur = db.cursor(dictionary=True)
    cur.execute("SELECT senha_hash FROM usuarios WHERE id=%s AND ativo=1", (g.user_id,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'success': False, 'message': 'Usuário não encontrado.'}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user['senha_hash'].encode('utf-8')):
        audit("DELETE_SENHA_INCORRETA")
        db_audit("DELETE_SENHA_INCORRETA")
        return jsonify({'success': False, 'message': 'Senha incorreta.'}), 401

    cur = db.cursor()
    # Soft delete — preserva histórico de auditoria
    cur.execute(
        "UPDATE usuarios SET ativo=0, email=CONCAT(email,'_deleted_',id) WHERE id=%s",
        (g.user_id,)
    )
    cur.execute("UPDATE sessoes SET revogado=1 WHERE usuario_id=%s", (g.user_id,))
    db.commit()
    cur.close()

    audit("CONTA_DELETADA")
    db_audit("CONTA_DELETADA")

    resp = make_response(jsonify({'success': True, 'message': 'Conta excluída.'}))
    resp.delete_cookie('mf_token')
    return resp

# ─── PERSONAL TRAINERS E TREINOS ──────────────────────────────────────────────
import random as _random

PERSONALS = [
    {'id':1,'nome':'Felipe Andrade','especialidade':'Musculação e Hipertrofia','genero':'M','objetivo':'hipertrofia'},
    {'id':2,'nome':'Bruno Carvalho','especialidade':'Treino Funcional','genero':'M','objetivo':'funcional'},
    {'id':3,'nome':'Matheus Oliveira','especialidade':'Condicionamento Físico','genero':'M','objetivo':'condicionamento'},
    {'id':4,'nome':'Gustavo Martins','especialidade':'Força e Resistência','genero':'M','objetivo':'forca'},
    {'id':5,'nome':'Daniel Rocha','especialidade':'Acompanhamento Iniciante','genero':'M','objetivo':'saude'},
    {'id':6,'nome':'Victor Almeida','especialidade':'Personal Trainer','genero':'M','objetivo':None},
    {'id':7,'nome':'Amanda Ribeiro','especialidade':'Treino Feminino','genero':'F','objetivo':None},
    {'id':8,'nome':'Júlia Fernandes','especialidade':'Glúteos e Pernas','genero':'F','objetivo':'emagrecimento'},
    {'id':9,'nome':'Camila Duarte','especialidade':'Emagrecimento e Cardio','genero':'F','objetivo':'emagrecimento'},
    {'id':10,'nome':'Bianca Monteiro','especialidade':'Funcional e Mobilidade','genero':'F','objetivo':'funcional'},
    {'id':11,'nome':'Larissa Alves','especialidade':'Aulas Coletivas','genero':'F','objetivo':'condicionamento'},
    {'id':12,'nome':'Fernanda Costa','especialidade':'Personal Trainer','genero':'F','objetivo':None},
]

TREINOS = {
    'hipertrofia': [
        {'dia':'A – Peito & Tríceps','exercicios':[['Supino Reto','4x10','70 kg','90s'],['Supino Inclinado Haltere','3x12','24 kg','75s'],['Crucifixo','3x15','14 kg','60s'],['Tríceps Pulley','4x12','35 kg','60s'],['Tríceps Francês','3x12','20 kg','60s']]},
        {'dia':'B – Costas & Bíceps','exercicios':[['Puxada Frontal','4x10','65 kg','90s'],['Remada Curvada','4x10','60 kg','90s'],['Remada Unilateral','3x12','26 kg','75s'],['Rosca Direta','4x12','20 kg','60s'],['Rosca Martelo','3x12','18 kg','60s']]},
        {'dia':'C – Pernas','exercicios':[['Agachamento Livre','5x8','80 kg','120s'],['Leg Press 45°','4x12','160 kg','90s'],['Cadeira Extensora','3x15','60 kg','60s'],['Leg Curl Deitado','3x15','50 kg','60s'],['Panturrilha em Pé','4x20','100 kg','45s']]},
    ],
    'emagrecimento': [
        {'dia':'A – HIIT + Upper','exercicios':[['Esteira HIIT','20 min','—','—'],['Supino Haltere','3x15','16 kg','45s'],['Puxada Alta','3x15','50 kg','45s'],['Flexão de Braço','3x20','Corporal','30s'],['Abdominal','4x20','Corporal','30s']]},
        {'dia':'B – Cardio + Core','exercicios':[['Bike Ergométrica','30 min','Nível 7','—'],['Elíptico','20 min','Nível 6','—'],['Prancha','3x45s','Corporal','30s'],['Mountain Climber','4x30s','Corporal','30s'],['Burpee','3x12','Corporal','45s']]},
        {'dia':'C – Lower Body','exercicios':[['Agachamento Sumo','4x15','50 kg','60s'],['Stiff','4x12','50 kg','60s'],['Abdutora','3x20','40 kg','45s'],['Escada Simuladora','15 min','—','—'],['Afundo','3x12 cada','Corporal','45s']]},
    ],
    'condicionamento': [
        {'dia':'A – Aeróbico','exercicios':[['Corrida Esteira','40 min','Nível 8','—'],['Bike Indoor','20 min','Nível 7','—'],['Pular Corda','5x3 min','Corporal','60s'],['Burpee','4x15','Corporal','30s'],['Mountain Climber','4x30s','Corporal','30s']]},
        {'dia':'B – Resistência','exercicios':[['Agachamento','4x20','40 kg','45s'],['Flexão','4x20','Corporal','30s'],['Remada','4x20','40 kg','45s'],['Afundo','3x15/lado','Corporal','45s'],['Prancha Lateral','3x30s','Corporal','30s']]},
    ],
    'forca': [
        {'dia':'A – Força Máxima','exercicios':[['Agachamento Livre','5x5','100 kg','180s'],['Supino Reto','5x5','85 kg','180s'],['Terra (Deadlift)','5x5','120 kg','180s'],['Desenvolvimento','4x6','60 kg','120s'],['Barra Fixa','4x6','Corporal+10kg','120s']]},
        {'dia':'B – Acessórios','exercicios':[['Agachamento Búlgaro','4x8','30 kg','90s'],['Tríceps Testa','4x8','30 kg','75s'],['Remada Cavalinho','4x8','80 kg','90s'],['Rosca Scott','3x10','22 kg','60s'],['Panturrilha Livre','5x15','100 kg','45s']]},
    ],
    'saude': [
        {'dia':'A – Upper Leve','exercicios':[['Supino Haltere','3x12','12 kg','60s'],['Remada Baixa','3x12','40 kg','60s'],['Elevação Lateral','3x15','6 kg','45s'],['Rosca Direta','3x12','10 kg','45s'],['Tríceps Corda','3x12','20 kg','45s']]},
        {'dia':'B – Mobilidade & Core','exercicios':[['Bicicleta Ergométrica','20 min','Nível 5','—'],['Alongamento Global','10 min','—','—'],['Prancha','3x30s','Corporal','30s'],['Dead Bug','3x10/lado','Corporal','30s'],['Abdominal Básico','3x15','Corporal','30s']]},
    ],
    'funcional': [
        {'dia':'A – Core & Estabilidade','exercicios':[['Prancha','4x60s','Corporal','30s'],['Dead Bug','3x10/lado','Corporal','30s'],['Kettlebell Swing','4x15','16 kg','45s'],['TRX Linha','3x12','Corporal','45s'],['Slam Ball','4x10','8 kg','60s']]},
        {'dia':'B – Potência','exercicios':[['Box Jump','4x8','—','60s'],['Barra Fixa','4x8','Corporal','75s'],['Agachamento com Salto','4x10','Corporal','45s'],['Corda Naval','4x30s','—','60s'],['Pular Corda','5x2 min','—','45s']]},
    ],
}

def get_personal_para_objetivo(objetivo):
    candidatos = [p for p in PERSONALS if p['objetivo'] == objetivo]
    if not candidatos:
        candidatos = PERSONALS
    return _random.choice(candidatos)

def gerar_treino_do_dia(objetivo):
    dias = TREINOS.get(objetivo, TREINOS['saude'])
    return dias[_random.randint(0, len(dias) - 1)]

@app.route('/api/personal/meu')
@login_required
def api_meu_personal():
    db = get_db()
    if not db:
        return jsonify({'message': 'Serviço indisponível.'}), 503
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT objetivo FROM usuarios WHERE id=%s AND ativo=1", (g.user_id,))
    user = cur.fetchone()
    cur.close()
    objetivo = (user or {}).get('objetivo') or 'saude'
    if objetivo not in OBJS_OK:
        objetivo = 'saude'
    personal = get_personal_para_objetivo(objetivo)
    treino = gerar_treino_do_dia(objetivo)
    return jsonify({'personal': personal, 'treino': treino, 'objetivo': objetivo})

@app.route('/api/treino/novo')
@login_required
@limiter.limit("30 per hour")
def api_treino_novo():
    db = get_db()
    if not db:
        return jsonify({'message': 'Serviço indisponível.'}), 503
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT objetivo FROM usuarios WHERE id=%s AND ativo=1", (g.user_id,))
    user = cur.fetchone()
    cur.close()
    objetivo = (user or {}).get('objetivo') or 'saude'
    if objetivo not in OBJS_OK:
        objetivo = 'saude'
    treino = gerar_treino_do_dia(objetivo)
    return jsonify({'treino': treino, 'objetivo': objetivo})

# ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
@app.route('/health')
def health():
    db = get_db()
    db_ok = db is not None and db.is_connected()
    # Não expor detalhes técnicos em produção
    if IS_PROD:
        return jsonify({'status': 'ok' if db_ok else 'degraded'})
    return jsonify({'status': 'ok' if db_ok else 'degraded', 'db': db_ok})

# ─── ERROR HANDLERS — sem stack trace em produção ──────────────────────────────
@app.errorhandler(400)
def bad_request(e):
    if request.path.startswith('/api/'):
        return jsonify({'message': 'Requisição inválida.'}), 400
    return render_template('index.html'), 400

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'message': 'Rota não encontrada.'}), 404
    return render_template('index.html'), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'message': 'Método não permitido.'}), 405

@app.errorhandler(429)
def ratelimit_handler(e):
    audit("RATE_LIMIT_ATINGIDO")
    return jsonify({'success': False, 'message': 'Muitas tentativas. Aguarde e tente novamente.'}), 429

@app.errorhandler(500)
def internal_error(e):
    # Log interno detalhado, resposta genérica ao cliente
    log.error("Internal error: %s", e, exc_info=True)
    if request.path.startswith('/api/'):
        return jsonify({'message': 'Erro interno do servidor.'}), 500
    return render_template('index.html'), 500

# ─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        init_db()
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true' and not IS_PROD
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
