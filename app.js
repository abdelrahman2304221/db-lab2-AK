require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const pool = require('./db');

const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

async function renderTodos(req, res, errors, newTitle) {
  const [todos] = await pool.execute(
    'SELECT todo_id, title, is_done, created_at FROM todos WHERE user_id = ? ORDER BY todo_id DESC',
    [req.session.userId]
  );
  res.render('todos', { name: req.session.name, todos, errors, newTitle });
}

function checkTitle(raw) {
  const title = (raw || '').trim();
  const errors = [];
  if (!title) errors.push('Title is required');
  else if (title.length > 200) errors.push('Title is too long (200 characters at most)');
  return { title, errors };
}

app.get('/', (req, res) => {
  res.redirect(req.session.userId ? '/todos' : '/login');
});

app.get('/register', (req, res) => {
  res.render('register', { errors: [], values: {} });
});

app.post('/register', async (req, res) => {
  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim();
  const password = req.body.password || '';
  const confirm = req.body.confirm_password || '';

  const errors = [];
  if (!name) errors.push('Name is required');
  if (!email) errors.push('Email is required');
  if (!password) errors.push('Password is required');
  if (!confirm) errors.push('Confirm password is required');
  if (password && confirm && password !== confirm) errors.push('Passwords do not match');

  if (errors.length > 0) {
    return res.render('register', { errors, values: { name, email } });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.execute(
      'INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)',
      [email, name, hash]
    );
    req.session.userId = result.insertId;
    req.session.name = name;
    res.redirect('/todos');
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.render('register', { errors: ['Email Already Exists'], values: { name, email } });
    }
    console.error(err);
    res.status(500).send('Something went wrong');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { errors: [], values: {} });
});

app.post('/login', async (req, res) => {
  const email = (req.body.email || '').trim();
  const password = req.body.password || '';

  const errors = [];
  if (!email) errors.push('Email is required');
  if (!password) errors.push('Password is required');

  if (errors.length > 0) {
    return res.render('login', { errors, values: { email } });
  }

  try {
    const [rows] = await pool.execute(
      'SELECT user_id, name, password_hash FROM users WHERE email = ?',
      [email]
    );
    const user = rows[0];
    const ok = user && await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      return res.render('login', { errors: ['Invalid email or password'], values: { email } });
    }

    req.session.userId = user.user_id;
    req.session.name = user.name;
    res.redirect('/todos');
  } catch (err) {
    console.error(err);
    res.status(500).send('Something went wrong');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/todos', requireLogin, async (req, res) => {
  try {
    await renderTodos(req, res, [], '');
  } catch (err) {
    console.error(err);
    res.status(500).send('Something went wrong');
  }
});

app.post('/todos/add', requireLogin, async (req, res) => {
  const { title, errors } = checkTitle(req.body.title);
  try {
    if (errors.length > 0) return await renderTodos(req, res, errors, req.body.title || '');
    await pool.execute(
      'INSERT INTO todos (user_id, title) VALUES (?, ?)',
      [req.session.userId, title]
    );
    res.redirect('/todos');
  } catch (err) {
    console.error(err);
    res.status(500).send('Something went wrong');
  }
});

app.post('/todos/:id/edit', requireLogin, async (req, res) => {
  const { title, errors } = checkTitle(req.body.title);
  try {
    if (errors.length > 0) return await renderTodos(req, res, errors, '');
    await pool.execute(
      'UPDATE todos SET title = ? WHERE todo_id = ? AND user_id = ?',
      [title, req.params.id, req.session.userId]
    );
    res.redirect('/todos');
  } catch (err) {
    console.error(err);
    res.status(500).send('Something went wrong');
  }
});

app.post('/todos/:id/toggle', requireLogin, async (req, res) => {
  const isDone = req.body.is_done === '1' ? 1 : 0;
  try {
    await pool.execute(
      'UPDATE todos SET is_done = ? WHERE todo_id = ? AND user_id = ?',
      [isDone, req.params.id, req.session.userId]
    );
    res.redirect('/todos');
  } catch (err) {
    console.error(err);
    res.status(500).send('Something went wrong');
  }
});

app.post('/todos/:id/delete', requireLogin, async (req, res) => {
  try {
    await pool.execute(
      'DELETE FROM todos WHERE todo_id = ? AND user_id = ?',
      [req.params.id, req.session.userId]
    );
    res.redirect('/todos');
  } catch (err) {
    console.error(err);
    res.status(500).send('Something went wrong');
  }
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});