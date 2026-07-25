import sqlite3
import jwt
import re
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Troque em produção
CORS(app, supports_credentials=True, origins=[
    'http://127.0.0.1:5500', 'http://localhost:5500',
    'http://127.0.0.1:5501', 'http://localhost:5501',
    'http://127.0.0.1:5502', 'http://localhost:5502'
])

DATABASE = 'database.db'
JWT_SECRET = 'supersecretjwtkey'  # Troque em produção

# -------------------- VALIDAÇÃO DE E-MAIL --------------------
def email_valido(email):
    padrao = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(padrao, email) is not None

# -------------------- BANCO DE DADOS --------------------
def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL,
                tipo TEXT NOT NULL,
                avaliacao REAL DEFAULT 0,
                total_avaliacoes INTEGER DEFAULT 0,
                plano TEXT DEFAULT 'free',
                avatar TEXT,
                habilidades TEXT,
                localizacao TEXT,
                experiencia TEXT,
                curriculo TEXT
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS diarias (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                descricao TEXT,
                localizacao TEXT NOT NULL,
                valor REAL NOT NULL,
                categoria TEXT,
                duracao TEXT,
                status TEXT DEFAULT 'aberta',
                contratante_id INTEGER NOT NULL,
                data TEXT,
                horario TEXT,
                data_limite TEXT,
                destaque INTEGER DEFAULT 0,
                FOREIGN KEY(contratante_id) REFERENCES usuarios(id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS candidaturas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                diaria_id INTEGER NOT NULL,
                trabalhador_id INTEGER NOT NULL,
                status TEXT DEFAULT 'pendente',
                mensagem TEXT,
                FOREIGN KEY(diaria_id) REFERENCES diarias(id),
                FOREIGN KEY(trabalhador_id) REFERENCES usuarios(id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS avaliacoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                diaria_id INTEGER NOT NULL,
                trabalhador_id INTEGER NOT NULL,
                contratante_id INTEGER NOT NULL,
                nota INTEGER NOT NULL,
                comentario TEXT,
                recontratar TEXT,
                FOREIGN KEY(diaria_id) REFERENCES diarias(id),
                FOREIGN KEY(trabalhador_id) REFERENCES usuarios(id),
                FOREIGN KEY(contratante_id) REFERENCES usuarios(id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS mensagens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remetente_id INTEGER NOT NULL,
                destinatario_id INTEGER NOT NULL,
                texto TEXT NOT NULL,
                hora TEXT,
                FOREIGN KEY(remetente_id) REFERENCES usuarios(id),
                FOREIGN KEY(destinatario_id) REFERENCES usuarios(id)
            )
        ''')
        db.commit()


@app.route('/')
# -------------------- UTILITÁRIOS JWT --------------------
def gerar_token(usuario):
    payload = {
        'user_id': usuario['id'],
        'tipo': usuario['tipo'],
        'exp': datetime.now() + timedelta(days=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def usuario_por_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        db = get_db()
        user = db.execute('SELECT * FROM usuarios WHERE id = ?', (payload['user_id'],)).fetchone()
        return dict(user) if user else None
    except:
        return None

def get_usuario_logado():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        return usuario_por_token(token)
    return None

# -------------------- ROTAS DE AUTENTICAÇÃO --------------------
@app.route('/api/registro', methods=['POST'])
def registro():
    data = request.json
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')
    tipo = data.get('tipo')

    if not nome or not email or not senha or not tipo:
        return jsonify({'erro': 'Preencha todos os campos'}), 400

    if not email_valido(email):
        return jsonify({'erro': 'E-mail inválido'}), 400

    db = get_db()
    if db.execute('SELECT id FROM usuarios WHERE email = ?', (email,)).fetchone():
        return jsonify({'erro': 'E-mail já cadastrado'}), 400

    hash_senha = generate_password_hash(senha)
    cursor = db.execute(
        'INSERT INTO usuarios (nome, email, senha, tipo) VALUES (?, ?, ?, ?)',
        (nome, email, hash_senha, tipo)
    )
    db.commit()
    user_id = cursor.lastrowid
    user = dict(db.execute('SELECT * FROM usuarios WHERE id = ?', (user_id,)).fetchone())
    token = gerar_token(user)
    return jsonify({'token': token, 'usuario': user}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    senha = data.get('senha')
    tipo = data.get('tipo')

    if not email or not senha or not tipo:
        return jsonify({'erro': 'Preencha todos os campos'}), 400

    if not email_valido(email):
        return jsonify({'erro': 'E-mail inválido'}), 400

    db = get_db()
    user = db.execute('SELECT * FROM usuarios WHERE email = ? AND tipo = ?', (email, tipo)).fetchone()
    if not user or not check_password_hash(user['senha'], senha):
        return jsonify({'erro': 'Credenciais inválidas'}), 401

    user_dict = dict(user)
    token = gerar_token(user_dict)
    return jsonify({'token': token, 'usuario': user_dict}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    return jsonify({'ok': True}), 200

@app.route('/api/usuarios/me', methods=['GET'])
def me():
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401
    return jsonify(user), 200

@app.route('/api/usuarios/me', methods=['PUT'])
def atualizar_perfil():
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401

    data = request.json
    habilidades = data.get('habilidades')
    localizacao = data.get('localizacao')
    experiencia = data.get('experiencia')
    curriculo = data.get('curriculo')

    db = get_db()
    db.execute(
        'UPDATE usuarios SET habilidades = ?, localizacao = ?, experiencia = ?, curriculo = ? WHERE id = ?',
        (habilidades, localizacao, experiencia, curriculo, user['id'])
    )
    db.commit()
    user_atualizado = dict(db.execute('SELECT * FROM usuarios WHERE id = ?', (user['id'],)).fetchone())
    return jsonify(user_atualizado), 200

# -------------------- ROTAS DE DIÁRIAS --------------------
@app.route('/api/diarias', methods=['GET'])
def listar_diarias():
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401

    db = get_db()
    if user['tipo'] == 'trabalhador':
        hoje = datetime.now().strftime('%Y-%m-%d')
        diarias = db.execute(
            'SELECT * FROM diarias WHERE status = "aberta" AND (data_limite IS NULL OR data_limite >= ?) ORDER BY id DESC',
            (hoje,)
        ).fetchall()
    else:
        diarias = db.execute('SELECT * FROM diarias WHERE contratante_id = ? ORDER BY id DESC', (user['id'],)).fetchall()

    return jsonify([dict(row) for row in diarias]), 200

@app.route('/api/diarias', methods=['POST'])
def criar_diaria():
    user = get_usuario_logado()
    if not user or user['tipo'] != 'contratante':
        return jsonify({'erro': 'Apenas contratantes podem criar diárias'}), 403

    data = request.json
    titulo = data.get('titulo')
    descricao = data.get('descricao')
    localizacao = data.get('localizacao')
    valor = data.get('valor')
    categoria = data.get('categoria')
    duracao = data.get('duracao')
    data_limite = data.get('data_limite')

    if not titulo or not localizacao or not valor:
        return jsonify({'erro': 'Campos obrigatórios faltando'}), 400

    db = get_db()
    data_hoje = datetime.now().strftime('%d/%m/%Y')
    horario = '08h às 12h'
    cursor = db.execute(
        '''INSERT INTO diarias (titulo, descricao, localizacao, valor, categoria, duracao, contratante_id, data, horario, data_limite)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (titulo, descricao, localizacao, valor, categoria, duracao, user['id'], data_hoje, horario, data_limite)
    )
    db.commit()
    diaria = dict(db.execute('SELECT * FROM diarias WHERE id = ?', (cursor.lastrowid,)).fetchone())
    return jsonify(diaria), 201

@app.route('/api/diarias/<int:diaria_id>', methods=['PUT'])
def atualizar_diaria(diaria_id):
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401

    data = request.json
    status = data.get('status')

    db = get_db()
    diaria = db.execute('SELECT * FROM diarias WHERE id = ?', (diaria_id,)).fetchone()
    if not diaria:
        return jsonify({'erro': 'Diária não encontrada'}), 404
    if diaria['contratante_id'] != user['id']:
        return jsonify({'erro': 'Não autorizado'}), 403

    db.execute('UPDATE diarias SET status = ? WHERE id = ?', (status, diaria_id))
    db.commit()
    diaria = dict(db.execute('SELECT * FROM diarias WHERE id = ?', (diaria_id,)).fetchone())
    return jsonify(diaria), 200

# -------------------- ROTAS DE CANDIDATURAS --------------------
@app.route('/api/candidaturas', methods=['GET'])
def listar_candidaturas():
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401

    db = get_db()
    if user['tipo'] == 'trabalhador':
        candidaturas = db.execute(
            '''SELECT c.*, d.titulo as diaria_titulo, d.localizacao as diaria_local, d.valor as diaria_valor
               FROM candidaturas c JOIN diarias d ON c.diaria_id = d.id
               WHERE c.trabalhador_id = ?''',
            (user['id'],)
        ).fetchall()
    else:
        candidaturas = db.execute(
            '''SELECT c.*, u.nome as trabalhador_nome, u.avaliacao as trabalhador_avaliacao,
                      u.habilidades as trabalhador_habilidades, u.experiencia as trabalhador_experiencia,
                      u.curriculo as trabalhador_curriculo
               FROM candidaturas c
               JOIN usuarios u ON c.trabalhador_id = u.id
               JOIN diarias d ON c.diaria_id = d.id
               WHERE d.contratante_id = ?''',
            (user['id'],)
        ).fetchall()

    return jsonify([dict(row) for row in candidaturas]), 200

@app.route('/api/candidaturas', methods=['POST'])
def criar_candidatura():
    user = get_usuario_logado()
    if not user or user['tipo'] != 'trabalhador':
        return jsonify({'erro': 'Apenas trabalhadores podem candidatar-se'}), 403

    data = request.json
    diaria_id = data.get('diaria_id')
    mensagem = data.get('mensagem', '')

    db = get_db()
    hoje = datetime.now().strftime('%Y-%m-%d')
    diaria = db.execute(
        'SELECT id, status, data_limite FROM diarias WHERE id = ? AND status = "aberta" AND (data_limite IS NULL OR data_limite >= ?)',
        (diaria_id, hoje)
    ).fetchone()
    if not diaria:
        return jsonify({'erro': 'Diária não está mais disponível para candidaturas'}), 400

    existe = db.execute(
        'SELECT id FROM candidaturas WHERE diaria_id = ? AND trabalhador_id = ?',
        (diaria_id, user['id'])
    ).fetchone()
    if existe:
        return jsonify({'erro': 'Você já se candidatou a esta diária'}), 400

    cursor = db.execute(
        'INSERT INTO candidaturas (diaria_id, trabalhador_id, mensagem, status) VALUES (?, ?, ?, "pendente")',
        (diaria_id, user['id'], mensagem)
    )
    db.commit()
    candidatura = dict(db.execute('SELECT * FROM candidaturas WHERE id = ?', (cursor.lastrowid,)).fetchone())
    return jsonify(candidatura), 201

@app.route('/api/candidaturas/<int:candidatura_id>', methods=['PUT'])
def atualizar_candidatura(candidatura_id):
    user = get_usuario_logado()
    if not user or user['tipo'] != 'contratante':
        return jsonify({'erro': 'Apenas contratantes podem responder candidaturas'}), 403

    data = request.json
    status = data.get('status')

    db = get_db()
    candidatura = db.execute('SELECT * FROM candidaturas WHERE id = ?', (candidatura_id,)).fetchone()
    if not candidatura:
        return jsonify({'erro': 'Candidatura não encontrada'}), 404

    diaria = db.execute('SELECT * FROM diarias WHERE id = ?', (candidatura['diaria_id'],)).fetchone()
    if diaria['contratante_id'] != user['id']:
        return jsonify({'erro': 'Não autorizado'}), 403

    db.execute('UPDATE candidaturas SET status = ? WHERE id = ?', (status, candidatura_id))
    if status == 'aceita':
        db.execute('UPDATE diarias SET status = "em_andamento" WHERE id = ?', (candidatura['diaria_id'],))
    db.commit()
    candidatura = dict(db.execute('SELECT * FROM candidaturas WHERE id = ?', (candidatura_id,)).fetchone())
    return jsonify(candidatura), 200

# -------------------- ROTAS DE AVALIAÇÕES --------------------
@app.route('/api/avaliacoes', methods=['POST'])
def criar_avaliacao():
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401

    data = request.json
    diaria_id = data.get('diaria_id')
    trabalhador_id = data.get('trabalhador_id')
    nota = data.get('nota')
    comentario = data.get('comentario')
    recontratar = data.get('recontratar')

    db = get_db()
    diaria = db.execute('SELECT * FROM diarias WHERE id = ? AND contratante_id = ?', (diaria_id, user['id'])).fetchone()
    if not diaria:
        return jsonify({'erro': 'Diária não encontrada ou não autorizada'}), 404

    trabalhador = db.execute('SELECT * FROM usuarios WHERE id = ?', (trabalhador_id,)).fetchone()
    if not trabalhador:
        return jsonify({'erro': 'Trabalhador não encontrado'}), 404

    nova_avaliacao = trabalhador['avaliacao'] * trabalhador['total_avaliacoes'] + nota
    novo_total = trabalhador['total_avaliacoes'] + 1
    media = nova_avaliacao / novo_total

    db.execute(
        'UPDATE usuarios SET avaliacao = ?, total_avaliacoes = ? WHERE id = ?',
        (media, novo_total, trabalhador_id)
    )

    db.execute(
        'INSERT INTO avaliacoes (diaria_id, trabalhador_id, contratante_id, nota, comentario, recontratar) VALUES (?, ?, ?, ?, ?, ?)',
        (diaria_id, trabalhador_id, user['id'], nota, comentario, recontratar)
    )
    db.commit()
    return jsonify({'ok': True}), 201

# -------------------- ROTAS DE MENSAGENS --------------------
@app.route('/api/mensagens/<int:destinatario_id>', methods=['GET'])
def listar_mensagens(destinatario_id):
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401

    db = get_db()
    mensagens = db.execute(
        '''SELECT * FROM mensagens
           WHERE (remetente_id = ? AND destinatario_id = ?)
              OR (remetente_id = ? AND destinatario_id = ?)
           ORDER BY id ASC''',
        (user['id'], destinatario_id, destinatario_id, user['id'])
    ).fetchall()
    return jsonify([dict(row) for row in mensagens]), 200

@app.route('/api/mensagens', methods=['POST'])
def enviar_mensagem():
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401

    data = request.json
    destinatario_id = data.get('destinatario_id')
    texto = data.get('texto')
    hora = datetime.now().strftime('%H:%M')

    db = get_db()
    cursor = db.execute(
        'INSERT INTO mensagens (remetente_id, destinatario_id, texto, hora) VALUES (?, ?, ?, ?)',
        (user['id'], destinatario_id, texto, hora)
    )
    db.commit()
    mensagem = dict(db.execute('SELECT * FROM mensagens WHERE id = ?', (cursor.lastrowid,)).fetchone())
    return jsonify(mensagem), 201

# -------------------- ROTAS DE ASSINATURA --------------------
@app.route('/api/assinatura', methods=['PUT'])
def atualizar_assinatura():
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401

    data = request.json
    plano = data.get('plano')

    db = get_db()
    db.execute('UPDATE usuarios SET plano = ? WHERE id = ?', (plano, user['id']))
    db.commit()
    user_atualizado = dict(db.execute('SELECT * FROM usuarios WHERE id = ?', (user['id'],)).fetchone())
    return jsonify(user_atualizado), 200

# -------------------- ROTAS PARA BUSCAR PROFISSIONAIS --------------------
@app.route('/api/profissionais', methods=['GET'])
def buscar_profissionais():
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401

    termo = request.args.get('q', '').lower()
    db = get_db()
    try:
        query = '''SELECT * FROM usuarios WHERE tipo = 'trabalhador' '''
        params = []
        if termo:
            query += ''' AND (LOWER(nome) LIKE ? OR LOWER(habilidades) LIKE ? OR LOWER(localizacao) LIKE ? OR LOWER(curriculo) LIKE ?)'''
            like = f'%{termo}%'
            params = [like, like, like, like]
        profissionais = db.execute(query, params).fetchall()
        return jsonify([dict(row) for row in profissionais]), 200
    except Exception as e:
        print(f"Erro em /api/profissionais: {e}")
        return jsonify({'erro': str(e)}), 500

# -------------------- ROTAS PARA LISTAR TODOS USUÁRIOS --------------------
@app.route('/api/usuarios', methods=['GET'])
def listar_usuarios():
    user = get_usuario_logado()
    if not user:
        return jsonify({'erro': 'Não logado'}), 401
    db = get_db()
    usuarios = db.execute('SELECT id, nome, avatar FROM usuarios WHERE id != ?', (user['id'],)).fetchall()
    return jsonify([dict(row) for row in usuarios]), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
@app.route('/')
def home():
    return render_template('index.html')
