const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

//Crea la aplicación
const app = express();
//permite recibir datos en formato JSON como {user,password}
app.use(express.json());
//permite que el frontend pueda hacer peticiones
app.use(cors());

//String para firmar los tokens que nunca se debe mostrar en público
const JWT_SECRET = 'secret_key';

// Conexión MongoDB local
mongoose.connect('mongodb://127.0.0.1:27017/usuariosjwt', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error to connect to MongoDB', err));

// Modelo de Usuario
const User = mongoose.model('user', new mongoose.Schema({
  user: String,
  password: String
}));

// Ruta para registrar usuarios
app.post('/register', async (req, res) => {
  //recibe user y password
  const { user, password } = req.body;
  //check si ya existe el usuario
  const existingUser = await User.findOne({ user });
  if (existingUser) return res.status(400).json({ status: 'error', response: 'User already exists' });

  //encripta la contraseña
  const hash = await bcrypt.hash(password, 10);

  //Crea el usuario y la guarda en base de datos
  const newUser = new User({ user, password: hash });
  await newUser.save();
  res.json({ status: 'ok', response: 'User registered' });
});

// Ruta de Login
app.post('/login', async (req, res) => {
  //recibe el usuario y la contraseña del front
  const { user, password } = req.body;
  const userLogginI = await User.findOne({ user });

  //Si el usuario que se logea no existe envia mensaje de error la respuesta
  if (!userLogginI) return res.status(400).json({ status: 'error', response: 'Incorrect credentials' });

  //devuelve true si la contraseña introducida que se cifra,
  //coincide con la contraseña cifrada de bd
  const isValid = await bcrypt.compare(password, userLogginI.password);
  //Si no coinciden contraseña incorrecta
  if (!isValid) return res.status(400).json({ status: 'error', response: 'Incorrect credentials' });

  //genera un token y lo devuelve
  const token = jwt.sign({ id: userLogginI._id, user: userLogginI.user }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ status: 'ok', response: token });
});

// Middleware para verificar token
function authenticateToken(req, res, next) {
  const header = req.headers['authorization'];
  const token = header && header.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Required token' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Ruta protegida
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Welcome to profile', user: req.user });
});

//Iniciar el servidor en el puerto 3000
app.listen(3000, () => console.log('Server listen in http://localhost:3000'));
