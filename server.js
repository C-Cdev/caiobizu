// server.js - Configurado para Produção com PostgreSQL
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

// Configurar o app Express
const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Configurar sessões
app.use(session({
    secret: process.env.SESSION_SECRET || 'meu-bizu-secreto-123',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Conectar com PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { 
        rejectUnauthorized: false 
    } : false
});

// Função helper para queries
async function query(text, params = []) {
    const client = await pool.connect();
    try {
        const result = await client.query(text, params);
        return result;
    } catch (error) {
        console.error('Database error:', error);
        throw error;
    } finally {
        client.release();
    }
}

// Testar conexão e criar tabelas
async function inicializarBanco() {
    try {
        await pool.query('SELECT NOW()');
        console.log('✅ Conectado ao banco PostgreSQL');
        await criarTabelas();
    } catch (error) {
        console.error('Erro ao conectar com banco:', error.message);
    }
}

// Função para criar as tabelas se não existirem
async function criarTabelas() {
    try {
        // Tabela de usuários
        await query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nome VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                senha VARCHAR(255) NOT NULL,
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Tabela usuarios criada/verificada');

        // Tabela de categorias
        await query(`
            CREATE TABLE IF NOT EXISTS categorias (
                id SERIAL PRIMARY KEY,
                nome VARCHAR(255) UNIQUE NOT NULL
            )
        `);
        console.log('✅ Tabela categorias criada/verificada');

        // Tabela de bizus
        await query(`
            CREATE TABLE IF NOT EXISTS bizus (
                id SERIAL PRIMARY KEY,
                titulo VARCHAR(255) NOT NULL,
                conteudo TEXT NOT NULL,
                categoria_id INTEGER REFERENCES categorias(id),
                autor_id INTEGER NOT NULL REFERENCES usuarios(id),
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Tabela bizus criada/verificada');

        await inserirCategoriasPadrao();
    } catch (error) {
        console.error('Erro ao criar tabelas:', error);
    }
}

// Inserir categorias padrão
async function inserirCategoriasPadrao() {
    const categorias = ['Matemática', 'Física', 'Química', 'Biologia', 'História', 'Geografia', 'Português', 'Inglês', 'Filosofia', 'Geral'];
    
    try {
        for (const categoria of categorias) {
            await query('INSERT INTO categorias (nome) VALUES ($1) ON CONFLICT (nome) DO NOTHING', [categoria]);
        }
        console.log('✅ Categorias padrão inseridas');
    } catch (error) {
        console.error('Erro ao inserir categorias:', error);
    }
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

        const result = await query(
            'INSERT INTO usuarios (nome, email, senha) VALUES ($1, $2, $3) RETURNING id',
            [nome, email, senhaCriptografada]
        );

        res.json({ 
            sucesso: true, 
            mensagem: 'Usuário registrado com sucesso!',
            userId: result.rows[0].id
        });

    } catch (error) {
        if (error.constraint === 'usuarios_email_key') {
            res.status(400).json({ erro: 'Email já está em uso' });
        } else {
            console.error('Erro no registro:', error);
            res.status(500).json({ erro: 'Erro interno do servidor' });
        }
    }
});

// Login do usuário
app.post('/api/login', async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ erro: 'Email e senha são obrigatórios' });
    }

    try {
        const result = await query('SELECT * FROM usuarios WHERE email = $1', [email]);
        const usuario = result.rows[0];

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

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ erro: 'Erro interno do servidor' });
    }
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
app.get('/api/bizus', async (req, res) => {
    const categoria = req.query.categoria;
    let queryText = `
        SELECT b.*, u.nome as autor_nome, c.nome as categoria_nome 
        FROM bizus b 
        JOIN usuarios u ON b.autor_id = u.id 
        LEFT JOIN categorias c ON b.categoria_id = c.id 
    `;
    let params = [];

    if (categoria && categoria !== 'todas') {
        queryText += ' WHERE c.nome = $1';
        params.push(categoria);
    }

    queryText += ' ORDER BY b.data_criacao DESC';

    try {
        const result = await query(queryText, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar bizus:', error);
        res.status(500).json({ erro: 'Erro interno do servidor' });
    }
});

// Criar novo bizu (só para usuários logados)
app.post('/api/bizus', verificarLogin, async (req, res) => {
    const { titulo, conteudo, categoria } = req.body;
    const autorId = req.session.userId;

    if (!titulo || !conteudo) {
        return res.status(400).json({ erro: 'Título e conteúdo são obrigatórios' });
    }

    try {
        let categoriaId = null;
        
        if (categoria) {
            const catResult = await query('SELECT id FROM categorias WHERE nome = $1', [categoria]);
            categoriaId = catResult.rows[0]?.id || null;
        }

        const result = await query(
            'INSERT INTO bizus (titulo, conteudo, categoria_id, autor_id) VALUES ($1, $2, $3, $4) RETURNING id',
            [titulo, conteudo, categoriaId, autorId]
        );

        res.json({ 
            sucesso: true, 
            mensagem: 'Bizu criado com sucesso!',
            bizuId: result.rows[0].id
        });

    } catch (error) {
        console.error('Erro ao criar bizu:', error);
        res.status(500).json({ erro: 'Erro interno do servidor' });
    }
});

// Listar categorias
app.get('/api/categorias', async (req, res) => {
    try {
        const result = await query('SELECT * FROM categorias ORDER BY nome');
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar categorias:', error);
        res.status(500).json({ erro: 'Erro interno do servidor' });
    }
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

// Inicializar banco e servidor
inicializarBanco().then(() => {
    app.listen(PORT, () => {
        console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
        console.log('📝 Para parar o servidor: Ctrl + C');
    });
});

// Fechar pool ao encerrar aplicação
process.on('SIGINT', async () => {
    console.log('\n🔄 Encerrando servidor...');
    try {
        await pool.end();
        console.log('✅ Pool PostgreSQL fechado');
    } catch (error) {
        console.error('Erro ao fechar pool:', error);
    }
    process.exit(0);
});
