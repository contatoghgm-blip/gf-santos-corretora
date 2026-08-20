// ============================================================
// Backend do Sistema G F Santos Corretora
// Conecta o front-end (index.html) ao banco de dados Neon
// (substitui o antigo armazenamento local IndexedDB)
// ============================================================
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error('ERRO: variável de ambiente DATABASE_URL não configurada.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname)));

const STORES = ['imoveis','proprietarios','inquilinos','fiadores','contratos','vistorias','manutencoes','financeiro','ajustes','corretores','comissoes','apolices','config','rascunhos','clientes'];

// ------------------------------------------------------------
// Sessões simples em memória (token -> usuário). Válidas até o
// processo reiniciar; suficiente para uso interno de uma equipe pequena.
// ------------------------------------------------------------
const sessions = new Map();

function gerarToken() {
  return crypto.randomBytes(32).toString('hex');
}

function verificarSenha(senha, hashArmazenado, saltArmazenado) {
  const hash = crypto.pbkdf2Sync(senha, Buffer.from(saltArmazenado, 'base64'), 100000, 32, 'sha256');
  return hash.toString('base64') === hashArmazenado;
}

function exigirAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ erro: 'Não autenticado.' });
  }
  req.usuario = sessions.get(token);
  next();
}

// ------------------------------------------------------------
// Autenticação
// ------------------------------------------------------------
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body || {};
    if (!email || !senha) return res.status(400).json({ erro: 'Informe e-mail e senha.' });

    const { rows } = await pool.query(
      'SELECT id, nome, email, senha_hash, senha_salt, ativo FROM usuarios WHERE email = $1',
      [String(email).toLowerCase().trim()]
    );
    const usuario = rows[0];
    if (!usuario || !usuario.ativo || !verificarSenha(senha, usuario.senha_hash, usuario.senha_salt)) {
      return res.status(401).json({ erro: 'E-mail ou senha inválidos.' });
    }
    const token = gerarToken();
    sessions.set(token, { id: usuario.id, nome: usuario.nome, email: usuario.email });
    res.json({ token, usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno ao autenticar.' });
  }
});

app.post('/api/auth/logout', exigirAuth, (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/auth/me', exigirAuth, (req, res) => {
  res.json({ usuario: req.usuario });
});

// ------------------------------------------------------------
// Dados genéricos (equivalentes às antigas "object stores" do IndexedDB)
// ------------------------------------------------------------
function validarStore(store, res) {
  if (!STORES.includes(store)) {
    res.status(400).json({ erro: 'Área de dados inválida.' });
    return false;
  }
  return true;
}

// Listar tudo de uma área (ex.: todos os imóveis)
app.get('/api/data/:store', exigirAuth, async (req, res) => {
  const { store } = req.params;
  if (!validarStore(store, res)) return;
  try {
    const { rows } = await pool.query('SELECT data FROM app_data WHERE store = $1', [store]);
    res.json(rows.map(r => r.data));
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao carregar dados.' });
  }
});

// Buscar um item específico
app.get('/api/data/:store/:id', exigirAuth, async (req, res) => {
  const { store, id } = req.params;
  if (!validarStore(store, res)) return;
  try {
    const { rows } = await pool.query('SELECT data FROM app_data WHERE store = $1 AND id = $2', [store, id]);
    if (!rows[0]) return res.status(404).json({ erro: 'Não encontrado.' });
    res.json(rows[0].data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao carregar item.' });
  }
});

// Criar ou atualizar um item
app.put('/api/data/:store/:id', exigirAuth, async (req, res) => {
  const { store, id } = req.params;
  if (!validarStore(store, res)) return;
  try {
    const obj = Object.assign({}, req.body, { id: String(id) });
    await pool.query(
      `INSERT INTO app_data (store, id, data, atualizado_em) VALUES ($1, $2, $3, now())
       ON CONFLICT (store, id) DO UPDATE SET data = $3, atualizado_em = now()`,
      [store, String(id), JSON.stringify(obj)]
    );
    res.json(obj);
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao salvar item.' });
  }
});

// Apagar um item
app.delete('/api/data/:store/:id', exigirAuth, async (req, res) => {
  const { store, id } = req.params;
  if (!validarStore(store, res)) return;
  try {
    await pool.query('DELETE FROM app_data WHERE store = $1 AND id = $2', [store, id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao apagar item.' });
  }
});

// Apagar todos os itens de uma área
app.delete('/api/data/:store', exigirAuth, async (req, res) => {
  const { store } = req.params;
  if (!validarStore(store, res)) return;
  try {
    await pool.query('DELETE FROM app_data WHERE store = $1', [store]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao limpar área.' });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Qualquer outra rota devolve o index.html (aplicativo de página única)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
