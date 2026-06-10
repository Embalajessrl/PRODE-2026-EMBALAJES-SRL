require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const JWT_SECRET = process.env.JWT_SECRET || 'prode2026secret';

// ─── MIDDLEWARE AUTH ─────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Token inválido' }); }
}

function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Solo admins' });
    next();
  });
}

// ─── HEALTH ──────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { firstName, lastName, email, password, department } = req.body;
  if (!firstName || !lastName || !email || !password)
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (exists.rows.length) return res.status(400).json({ error: 'El email ya está registrado' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (first_name, last_name, email, password, department, role, created_at) VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING id, first_name, last_name, email, department, role',
      [firstName, lastName, email, hash, department || null, 'USER']
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error del servidor' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, firstName: user.first_name, lastName: user.last_name, email: user.email, department: user.department, role: user.role } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error del servidor' }); }
});

app.get('/api/me', auth, async (req, res) => {
  const result = await pool.query('SELECT id, first_name, last_name, email, department, role FROM users WHERE id = $1', [req.user.id]);
  const u = result.rows[0];
  res.json({ id: u.id, firstName: u.first_name, lastName: u.last_name, email: u.email, department: u.department, role: u.role });
});

// ─── PARTIDOS (FIXTURES) ─────────────────────────────────────────────────────
app.get('/api/fixtures', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM fixtures ORDER BY match_date ASC');
  res.json(result.rows);
});

app.post('/api/fixtures', adminAuth, async (req, res) => {
  const { homeTeam, awayTeam, matchDate, stage } = req.body;
  const result = await pool.query(
    'INSERT INTO fixtures (home_team, away_team, match_date, stage, created_at) VALUES ($1,$2,$3,$4,NOW()) RETURNING *',
    [homeTeam, awayTeam, matchDate, stage || 'Fase de grupos']
  );
  res.status(201).json(result.rows[0]);
});

app.patch('/api/fixtures/:id/result', adminAuth, async (req, res) => {
  const { homeScore, awayScore } = req.body;
  const { id } = req.params;
  try {
    await pool.query(
      'UPDATE fixtures SET home_score=$1, away_score=$2, status=$3 WHERE id=$4',
      [homeScore, awayScore, 'FINISHED', id]
    );
    // Calcular puntos para todos los pronósticos de este partido
    const predictions = await pool.query('SELECT * FROM predictions WHERE fixture_id = $1', [id]);
    for (const p of predictions.rows) {
      let points = 0;
      if (p.home_score === homeScore && p.away_score === awayScore) {
        points = 3; // Resultado exacto
      } else {
        const realWinner = homeScore > awayScore ? 'home' : awayScore > homeScore ? 'away' : 'draw';
        const predWinner = p.home_score > p.away_score ? 'home' : p.away_score > p.home_score ? 'away' : 'draw';
        if (realWinner === predWinner) points = 1; // Ganador correcto
      }
      await pool.query('UPDATE predictions SET points=$1 WHERE id=$2', [points, p.id]);
    }
    // Recalcular ranking
    await pool.query(`
      INSERT INTO rankings (user_id, total_points, updated_at)
      SELECT user_id, SUM(points), NOW() FROM predictions GROUP BY user_id
      ON CONFLICT (user_id) DO UPDATE SET total_points = EXCLUDED.total_points, updated_at = NOW()
    `);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error del servidor' }); }
});

// ─── PRONÓSTICOS ─────────────────────────────────────────────────────────────
app.get('/api/predictions/my', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT p.*, f.home_team, f.away_team, f.match_date, f.home_score as real_home, f.away_score as real_away, f.status
     FROM predictions p JOIN fixtures f ON p.fixture_id = f.id
     WHERE p.user_id = $1 ORDER BY f.match_date ASC`,
    [req.user.id]
  );
  res.json(result.rows);
});

app.post('/api/predictions', auth, async (req, res) => {
  const { fixtureId, homeScore, awayScore } = req.body;
  try {
    // Verificar que el partido no empezó
    const fixture = await pool.query('SELECT * FROM fixtures WHERE id = $1', [fixtureId]);
    if (!fixture.rows[0]) return res.status(404).json({ error: 'Partido no encontrado' });
    if (fixture.rows[0].status === 'FINISHED') return res.status(400).json({ error: 'El partido ya terminó' });
    if (new Date(fixture.rows[0].match_date) < new Date()) return res.status(400).json({ error: 'El partido ya comenzó' });

    // Upsert pronóstico
    const result = await pool.query(
      `INSERT INTO predictions (user_id, fixture_id, home_score, away_score, created_at)
       VALUES ($1,$2,$3,$4,NOW())
       ON CONFLICT (user_id, fixture_id) DO UPDATE SET home_score=$3, away_score=$4
       RETURNING *`,
      [req.user.id, fixtureId, homeScore, awayScore]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error del servidor' }); }
});

// ─── RANKING ──────────────────────────────────────────────────────────────────
app.get('/api/ranking', auth, async (req, res) => {
  const result = await pool.query(`
    SELECT u.id, u.first_name, u.last_name, u.department,
           COALESCE(r.total_points, 0) as total_points,
           COALESCE(COUNT(p.id) FILTER (WHERE p.points = 3), 0) as exact_results,
           COALESCE(COUNT(p.id) FILTER (WHERE p.points = 1), 0) as correct_winners
    FROM users u
    LEFT JOIN rankings r ON u.id = r.user_id
    LEFT JOIN predictions p ON u.id = p.user_id
    WHERE u.role = 'USER'
    GROUP BY u.id, u.first_name, u.last_name, u.department, r.total_points
    ORDER BY total_points DESC
  `);
  res.json(result.rows);
});

// ─── ADMIN: USUARIOS ──────────────────────────────────────────────────────────
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const result = await pool.query('SELECT id, first_name, last_name, email, department, role, created_at FROM users ORDER BY created_at DESC');
  res.json(result.rows);
});

// ─── SETUP: CREAR TABLAS ──────────────────────────────────────────────────────
app.post('/api/setup', async (req, res) => {
  const { secret } = req.body;
  if (secret !== process.env.SETUP_SECRET) return res.status(403).json({ error: 'No autorizado' });
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        department VARCHAR(100),
        role VARCHAR(20) DEFAULT 'USER',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS fixtures (
        id SERIAL PRIMARY KEY,
        home_team VARCHAR(100) NOT NULL,
        away_team VARCHAR(100) NOT NULL,
        match_date TIMESTAMP NOT NULL,
        stage VARCHAR(100) DEFAULT 'Fase de grupos',
        home_score INTEGER,
        away_score INTEGER,
        status VARCHAR(20) DEFAULT 'SCHEDULED',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS predictions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        fixture_id INTEGER REFERENCES fixtures(id),
        home_score INTEGER NOT NULL,
        away_score INTEGER NOT NULL,
        points INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, fixture_id)
      );
      CREATE TABLE IF NOT EXISTS rankings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE REFERENCES users(id),
        total_points INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);
    // Crear admin por defecto
    const adminExists = await pool.query("SELECT id FROM users WHERE email = 'admin@empresa.com'");
    if (!adminExists.rows.length) {
      const hash = await bcrypt.hash('Admin2026!', 10);
      await pool.query(
        "INSERT INTO users (first_name, last_name, email, password, role) VALUES ('Admin', 'Sistema', 'admin@empresa.com', $1, 'ADMIN')",
        [hash]
      );
    }
    res.json({ success: true, message: 'Tablas creadas y admin listo' });
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Prode Mundial 2026 corriendo en puerto ${PORT}`));
