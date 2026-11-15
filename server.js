require('dotenv').config();

const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const BASE_URL = process.env.BASE_URL;

app.get('/config.js', (req, res) => {
  res.type('application/javascript').send(
    `window.BASE_URL = ${JSON.stringify(BASE_URL)};`
  );
});

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PROD = process.env.RENDER;
const flags = { sqli: true, csrf: true };


// ----------SQL umetanje ----------

const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, pin TEXT, secret TEXT);
  INSERT INTO users(username, pin, secret) VALUES
   ('admin','4921','TAJNA ADMINA: kljuc-ABC-123'),
   ('marko','1234','Markova privatna poruka'),
   ('ana','5678','Anina privatna poruka');
`);

db.exec(`
  CREATE TABLE messages(id INTEGER PRIMARY KEY, author TEXT, body TEXT);
  INSERT INTO messages(author, body) VALUES
   ('marko','Pozdrav svima, kako ste?'),
   ('ana','Vidimo se sutra na faksu.');
`);


app.post('/api/sqli', (req, res) => {
  const username = String(req.body.username ?? '');
  const pin = String(req.body.pin ?? '');
  let sql;
  try {
    let rows;
    if (flags.sqli) {
      // RANJIVO
      sql = `SELECT id, username, secret FROM users WHERE username = '${username}' AND pin = '${pin}'`;
      rows = db.prepare(sql).all();
    } else {
      // ZASTICENO
      sql = 'SELECT id, username, secret FROM users WHERE username = ? AND pin = ?';
      rows = db.prepare(sql).all(username, pin);
    }
    res.json({ vulnerable: flags.sqli, sql, params: flags.sqli ? [] : [username, pin], rows });
  } catch (e) {
    res.status(400).json({ vulnerable: flags.sqli, sql, error: e.message });
  }
});

app.post('/api/search', (req, res) => {
  const q = String(req.body.q ?? '');
  let sql;
  try {
    let rows;
    if (flags.sqli) {
      // RANJIVO
      sql = `SELECT author, body FROM messages WHERE body = '${q}'`;
      rows = db.prepare(sql).all();
    } else {
      // ZASTICENO
      sql = 'SELECT author, body FROM messages WHERE body = ?';
      rows = db.prepare(sql).all(q);
    }
    res.json({ vulnerable: flags.sqli, sql, rows });
  } catch (e) {
    res.status(400).json({ vulnerable: flags.sqli, sql, error: e.message });
  }
});


// ---------- CSRF ----------

const accounts = { alice: { password: 'alice123', balance: 1000 }, mallory: { password: 'mallory123', balance: 0 } };
let transactions = [];
const sessions = new Map(); // sid -> { user, csrf }

const getCookie = (req, name) => {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return c ? decodeURIComponent(c.slice(name.length + 1)) : null;
};
const sessionOf = req => sessions.get(getCookie(req, 'sid'));

app.get('/nagrada', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'attacker.html'));
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const acc = accounts[username];
  if (!acc || acc.password !== password) return res.status(401).json({ error: 'Pogrešno korisničko ime ili zaporka' });
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { user: username, csrf: crypto.randomBytes(24).toString('hex') });
  // SameSite=None je nužan da bi preglednik slao kolacic i u zahtjevima s drugog sjedista
  res.cookie('sid', sid, { httpOnly: true, secure: PROD, sameSite: PROD ? 'none' : undefined });
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  sessions.delete(getCookie(req, 'sid'));
  res.clearCookie('sid', { secure: PROD, sameSite: PROD ? 'none' : undefined });
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const s = sessionOf(req);
  if (!s) return res.json({ user: null });
  res.json({
    user: s.user, balance: accounts[s.user].balance, csrfToken: s.csrf,
    transactions: transactions.filter(t => t.from === s.user || t.to === s.user),
    balances: Object.fromEntries(Object.entries(accounts).map(([k, v]) => [k, v.balance]))
  });
});

app.post('/api/transfer', (req, res) => {
  const s = sessionOf(req);
  if (!s) return res.status(401).json({ error: 'Niste prijavljeni' });
  if (flags.csrf) {
    // RANJIVO: provjerava se samo kolacic sjednice, koji preglednik salje automatski
  } else {
    // ZASTICENO: synchronizer token koji napadac s drugog sjedišta ne moze procitati
    const token = req.get('x-csrf-token') || req.body._csrf;
    if (!token || token !== s.csrf) return res.status(403).json({ error: 'CSRF token nedostaje ili nije ispravan - zahtjev odbijen' });
  }
  const to = String(req.body.to), amount = Number(req.body.amount);
  if (!accounts[to] || !(amount > 0) || amount > accounts[s.user].balance)
    return res.status(400).json({ error: 'Neispravan primatelj ili iznos' });
  accounts[s.user].balance -= amount; accounts[to].balance += amount;
  transactions.push({ from: s.user, to, amount, time: new Date().toISOString() });
  res.json({ ok: true, message: `Prebačeno ${amount} EUR korisniku ${to}` });
});



// ---------- prekidači i reset ----------

app.get('/api/flags', (req, res) => res.json(flags));
app.post('/api/flags', (req, res) => {
  const { name, value } = req.body;
  if (!(name in flags)) return res.status(400).json({ error: 'Nepoznat prekidač' });
  flags[name] = !!value; res.json(flags);
});
app.post('/api/reset', (req, res) => {
  accounts.alice.balance = 1000; accounts.mallory.balance = 0; transactions = []; res.json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => console.log('Pokrenuto na portu ' + (process.env.PORT || 3000)));
