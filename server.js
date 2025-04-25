const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const WebSocket = require('ws');

const app = express();
const PORT = 8080;

// In-memory “DB”
const users = {};  // { username: { passwordHash } }

// Middlewares
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: 'keyboard cat',             // change this to a real secret!
  resave: false,
  saveUninitialized: false,
}));

// Serve static HTML
app.use('/public', express.static(path.join(__dirname, 'public')));

// Simple auth check
function requireAuth(req, res, next) {
  if (req.session.username) return next();
  res.redirect('/login.html');
}

// Routes
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (users[username]) {
    return res.send('Username already exists! <a href="/register.html">Try again</a>');
  }
  const hash = await bcrypt.hash(password, 10);
  users[username] = { passwordHash: hash };
  req.session.username = username;
  res.redirect('/');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.send('Invalid creds! <a href="/login.html">Try again</a>');
  }
  req.session.username = username;
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// Start HTTP server
const server = app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

// WebSocket server
const wss = new WebSocket.Server({ server });
let clients = [];

wss.on('connection', (ws, req) => {
  // Authenticate based on session cookie
  // (In production, use a shared session store and parse cookies properly)
  const username = req.headers.cookie
    ?.split('; ')
    .find(c => c.startsWith('connect.sid='))
    ? req.session?.username 
    : null;

  if (!username) {
    ws.close();
    return;
  }

  clients.push({ ws, username });
  ws.on('message', msg => {
    const data = JSON.stringify({ from: username, text: msg });
    clients.forEach(c => {
      if (c.ws.readyState === WebSocket.OPEN) {
        c.ws.send(data);
      }
    });
  });

  ws.on('close', () => {
    clients = clients.filter(c => c.ws !== ws);
  });
});
