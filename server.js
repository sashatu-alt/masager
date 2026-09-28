const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

const users = [];
const messages = [];
const JWT_SECRET = 'secret';

// Регистрация
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
  if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Это имя уже занято' });
  const hashed = bcrypt.hashSync(password, 10);
  users.push({ username, password: hashed });
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username });
});

// Вход
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: 'Пользователь не найден' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Неверный пароль' });
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username });
});

// WebSocket
wss.on('connection', ws => {
  ws.username = null;

  ws.on('message', data => {
    const msg = JSON.parse(data.toString());

    if (msg.type === 'authenticate') {
      try {
        const payload = jwt.verify(msg.token, JWT_SECRET);
        ws.username = payload.username;
        ws.send(JSON.stringify({ type: 'authenticated', username: ws.username }));
      } catch (e) {
        ws.send(JSON.stringify({ type: 'error', error: 'Неверный токен' }));
        ws.close();
      }
    } else if (msg.type === 'message' && ws.username) {
      const text = msg.text.trim();
      if (!text || text.length > 500) return;
      const message = {
        type: 'message',
        username: ws.username,
        text,
        time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
      };
      messages.push(message);
      if (messages.length > 100) messages.shift();
      wss.clients.forEach(c => {
        if (c.readyState === WebSocket.OPEN) {
          c.send(JSON.stringify(message));
        }
      });
    }
  });

  // Отправляем историю сообщений новому подключению
  if (messages.length > 0) {
    ws.send(JSON.stringify({ type: 'history', messages }));
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
