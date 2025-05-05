const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

//Crea la aplicación
const app = express();
//permite recibir datos en formato JSON como {user,password}
app.use(express.json());
//permite que el frontend pueda hacer peticiones
app.use(cors());

//String para firmar los tokens que nunca se debe mostrar en público
const JWT_SECRET = "secret_key";

// Conexión MongoDB local
mongoose
  .connect("mongodb://127.0.0.1:27017/usuariosjwt", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Error to connect to MongoDB", err));

// Modelo de Usuario
const User = mongoose.model(
  "user",
  new mongoose.Schema({
    user: String,
    password: String,
  })
);

//Model patient
const Patients = mongoose.model(
  "patients",
  new mongoose.Schema({
    idPatient: Number,
    name: String,
    dni: String,
    telephone: String,
    email: String,
    postalCode: String,
    gender: String,
    dateOfBirth: String,
    address: String,
    token: String,
  })
);

// Ruta para registrar usuarios
app.post("/register", async (req, res) => {
  //recibe user y password
  const { user, password } = req.body;
  //check si ya existe el usuario
  const existingUser = await User.findOne({ user });
  if (existingUser)
    return res
      .status(400)
      .json({ status: "error", result: "User already exists" });

  //encripta la contraseña
  const hash = await bcrypt.hash(password, 10);

  //Crea el usuario y la guarda en base de datos
  const newUser = new User({ user, password: hash });
  await newUser.save();
  res.json({ status: "ok", result: "User registered" });
});

// Ruta de Login
app.post("/login", async (req, res) => {
  //recibe el usuario y la contraseña del front
  const { user, password } = req.body;
  const userLogginI = await User.findOne({ user });

  //Si el usuario que se logea no existe envia mensaje de error la respuesta
  if (!userLogginI)
    return res
      .status(400)
      .json({ status: "error", result: "Incorrect credentials" });

  //devuelve true si la contraseña introducida que se cifra,
  //coincide con la contraseña cifrada de bd
  const isValid = await bcrypt.compare(password, userLogginI.password);
  //Si no coinciden contraseña incorrecta
  if (!isValid)
    return res
      .status(400)
      .json({ status: "error", result: "Incorrect credentials" });

  //genera un token y lo devuelve
  const token = jwt.sign(
    { id: userLogginI._id, user: userLogginI.user },
    JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.json({ status: "ok", result: token });
});

app.get("/patients", async (req, res) => {
  try {
    //keep the number of page recovered from Frontend
    const page = parseInt(req.query.page) || 1;

    //keep number of records to show
    const recordsPerPage = 10;
    //keep the number of the record which db search records
    const recordsToSkip = (page - 1) * recordsPerPage;

    //.skip() -> from where it begins to search for patients in the database.
    //.limit() -> maximum number of records to show
    const patients = await Patients.find()
      .skip(recordsToSkip)
      .limit(recordsPerPage);

    res.json(patients);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching patients" });
  }
});

app.get("/patients/patient", async (req, res) => {
  try {
    const id = parseInt(req.query.id);
    const patient = await Patients.findOne({ idPatient: id });
    res.json(patient);
  } catch (error) {
    res.status(500).json({ error: "Error fetching patients" });
  }
});

app.put("/update-patient", async (req, res) => {
  try {
    
    //validate field idPatient
    if(!req.body.idPatient) {
      return res.status(400).send({
        message: 'error, required field',
        fields: req.body.idPatient
      })
    }

    const updatedPatient = await Patients.findOneAndUpdate(
      { idPatient: req.body.idPatient },
      req.body,
      { new: true } //parameter to return updatedPatient
    );

    if(!updatedPatient) {
      return res.status(404).send({ message: 'Patient not found' });
    } else {
      res.send(updatedPatient);
    }

  } catch (err) {
    console.error('Error updating patient:', err);
    res.status(500).send({ message: 'Server error' });
  }
});

app.delete("/delete-patient/:idPatient", async(req,res) => {

  const { idPatient } = req.params;

  try {
    const result = await Patients.deleteOne({ idPatient: idPatient });

    if (result.deletedCount === 0) {
      return res.status(404).json({ status: "error", result: "Patient not found" });
    }

    return res.json({ status: "ok", result: "Successfully deleted patient" });

  } catch(err) {
    return res
      .status(500)
      .json({ status: "error", result: "Error deleting patient" });
  }

  // const id = parseInt(req.body.idPatient)
  // const idFromDB = Patients.findByIdAndDelete(req.body.idPatient, function(err, do))
})

// Middleware para verificar token
function authenticateToken(req, res, next) {
  const header = req.headers["authorization"];
  const token = header && header.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Required token" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// Ruta protegida
app.get("/profile", authenticateToken, (req, res) => {
  res.json({ message: "Welcome to profile", user: req.user });
});

//Iniciar el servidor en el puerto 3000
app.listen(3000, () => console.log("Server listen in http://localhost:3000"));
