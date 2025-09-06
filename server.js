// server.js - Configurado para Produção
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

// Configurar o app Express
const app = express();
const PORT = process.env.PORT || 3000; // Railway define a porta automaticamente

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Configurar sessões - usando variável de ambiente para produção
app.use(session({
    secret: process.env.SESSION_SECRET || 'meu-bizu-secreto-123',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Railway usa HTTPS automático
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Conectar com banco SQLite
const dbPath = process.env.DATABASE_URL || './database/database.db';
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Erro ao conectar com banco:', err.message);
    } else {
        console.log('✅ Conectado ao banco SQLite');
        criarTabelas();
    }
});

// Função para criar as tabelas se não existirem
function criarTabelas() {
    // Tabela de usuários
    db.run(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('Erro ao criar tabela usuarios:', err);
        else console.log('✅ Tabela usuarios criada/verificada');
    });

    // Tabela de categorias
    db.run(`
        CREATE TABLE IF NOT EXISTS categorias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL
        )
    `, (err) => {
        if (err) console.error('Erro ao criar tabela categorias:', err);
        else {
            console.log('✅ Tabela categorias criada/verificada');
            inserirCategoriasPadrao();
        }
    });

    // Tabela de bizus
    db.run(`
        CREATE TABLE IF NOT EXISTS bizus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            conteudo TEXT NOT NULL,
            categoria_id INTEGER,
            autor_id INTEGER NOT NULL,
            data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (categoria_id) REFERENCES categorias(id),
            FOREIGN KEY (autor_id) REFERENCES usuarios(id)
        )
    `, (err) => {
        if (err) console.error('Erro ao criar tabela bizus:', err);
        else console.log('✅ Tabela bizus criada/verificada');
    });
}

// Inserir categorias padrão
function inserirCategoriasPadrao() {
    const categorias = ['Matemática', 'Física', 'Química', 'Biologia', 'História', 'Geografia', 'Português', 'Inglês', 'Filosofia', 'Geral'];
    
    categorias.forEach(categoria => {
        db.run('INSERT OR IGNORE INTO categorias (nome) VALUES (?)', [categoria]);
    });
    console.log('✅ Categorias padrão inseridas');
}

// Middleware para verificar se usuário está logado
function verificarLogin(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ erro: 'Usuário não está logado' });
    }
}

// ==================== ROTAS PRINCIPAIS ====================

// Página inicial - redireciona baseado no login
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
        res.sendFile(path.join(__dirname, 'public', 'login.html'));
    }
});

// ==================== ROTAS DE AUTENTICAÇÃO ====================

// Registrar novo usuário
app.post('/api/register', async (req, res) => {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
        return res.status(400).json({ erro: 'Todos os campos são obrigatórios' });
    }

    if (senha.length < 6) {
        return res.status(400).json({ erro: 'Senha deve ter pelo menos 6 caracteres' });
    }

    try {
        const senhaCriptografada = await bcrypt.hash(senha, 10);

        db.run(
            'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
            [nome, email, senhaCriptografada],
            function(err) {
                if (err) {
                    if (err.code === 'SQLITE_CONSTRAINT') {
                        res.status(400).json({ erro: 'Email já está em uso' });
                    } else {
                        res.status(500).json({ erro: 'Erro interno do servidor' });
                    }
                } else {
                    res.json({ 
                        sucesso: true, 
                        mensagem: 'Usuário registrado com sucesso!',
                        userId: this.lastID 
                    });
                }
            }
        );
    } catch (error) {
        res.status(500).json({ erro: 'Erro interno do servidor' });
    }
});

// Login do usuário
app.post('/api/login', (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ erro: 'Email e senha são obrigatórios' });
    }

    db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, usuario) => {
        if (err) {
            return res.status(500).json({ erro: 'Erro interno do servidor' });
        }

        if (!usuario) {
            return res.status(401).json({ erro: 'Email ou senha incorretos' });
        }

        const senhaCorreta = await bcrypt.compare(senha, usuario.senha);
        
        if (!senhaCorreta) {
            return res.status(401).json({ erro: 'Email ou senha incorretos' });
        }

        req.session.userId = usuario.id;
        req.session.userName = usuario.nome;

        res.json({ 
            sucesso: true, 
            mensagem: 'Login realizado com sucesso!',
            usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email }
        });
    });
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ erro: 'Erro ao fazer logout' });
        }
        res.json({ sucesso: true, mensagem: 'Logout realizado com sucesso' });
    });
});

// ==================== ROTAS DOS BIZUS ====================

// Listar todos os bizus (com filtro opcional por categoria)
app.get('/api/bizus', (req, res) => {
    const categoria = req.query.categoria;
    let query = `
        SELECT b.*, u.nome as autor_nome, c.nome as categoria_nome 
        FROM bizus b 
        JOIN usuarios u ON b.autor_id = u.id 
        LEFT JOIN categorias c ON b.categoria_id = c.id 
    `;
    let params = [];

    if (categoria && categoria !== 'todas') {
        query += ' WHERE c.nome = ?';
        params.push(categoria);
    }

    query += ' ORDER BY b.data_criacao DESC';

    db.all(query, params, (err, bizus) => {
        if (err) {
            console.error('Erro ao buscar bizus:', err);
            return res.status(500).json({ erro: 'Erro interno do servidor' });
        }
        res.json(bizus);
    });
});

// Criar novo bizu (só para usuários logados)
app.post('/api/bizus', verificarLogin, (req, res) => {
    const { titulo, conteudo, categoria } = req.body;
    const autorId = req.session.userId;

    if (!titulo || !conteudo) {
        return res.status(400).json({ erro: 'Título e conteúdo são obrigatórios' });
    }

    db.get('SELECT id FROM categorias WHERE nome = ?', [categoria], (err, cat) => {
        const categoriaId = cat ? cat.id : null;

        db.run(
            'INSERT INTO bizus (titulo, conteudo, categoria_id, autor_id) VALUES (?, ?, ?, ?)',
            [titulo, conteudo, categoriaId, autorId],
            function(err) {
                if (err) {
                    console.error('Erro ao criar bizu:', err);
                    return res.status(500).json({ erro: 'Erro interno do servidor' });
                }
                res.json({ 
                    sucesso: true, 
                    mensagem: 'Bizu criado com sucesso!',
                    bizuId: this.lastID 
                });
            }
        );
    });
});

// Listar categorias
app.get('/api/categorias', (req, res) => {
    db.all('SELECT * FROM categorias ORDER BY nome', (err, categorias) => {
        if (err) {
            return res.status(500).json({ erro: 'Erro interno do servidor' });
        }
        res.json(categorias);
    });
});

// Verificar status de login
app.get('/api/status', (req, res) => {
    if (req.session.userId) {
        res.json({ 
            logado: true, 
            usuario: { 
                id: req.session.userId, 
                nome: req.session.userName 
            } 
        });
    } else {
        res.json({ logado: false });
    }
});

// ==================== INICIAR SERVIDOR ====================

app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
    console.log('📝 Para parar o servidor: Ctrl + C');
});

// Fechar banco ao encerrar aplicação
process.on('SIGINT', () => {
    console.log('\n🔄 Encerrando servidor...');
    db.close((err) => {
        if (err) {
            console.error('Erro ao fechar banco:', err.message);
        } else {
            console.log('✅ Banco fechado');
        }
        process.exit(0);
    });
});