require('dotenv').config();
const User = require('./models/User');
const express = require('express');
const connectDB = require('./db.js');
const bcrypt = require("bcrypt");
const cors = require('cors');
const jwt = require("jsonwebtoken");
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 5000
const JWT_SECRET = process.env.JWT_SECRET;


const allowedOrigins = [
  'http://localhost:3000',
  'https://docora.rs',
  'https://www.docora.rs'
];

app.use(cors({
  origin: function(origin, callback) {
    if (origin && !allowedOrigins.includes(origin)) {
      return callback(new Error('CORS policy: Origin not allowed'), false);
    }
    return callback(null, true);
  },
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

connectDB();

app.post("/api/register", async (req, res) => {
  const { name, email, lozinka, delatnost, adresa } = req.body;

  if (!name || !email || !lozinka || !delatnost || !adresa) {
    return res.status(400).json({ error: "Sva polja su obavezna" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: "Korisnik već postoji" });
    }
    const hashedPassword = await bcrypt.hash(lozinka, 10);

    const newUser = new User({
      name,
      email,
      lozinka: hashedPassword,
      delatnost,
      adresa,
      isActive: true,
    });

    await newUser.save();

    return res.status(201).json({ message: "Uspešna registracija" });
  } catch (err) {
    console.error("Greška pri registraciji:", err);

    if (err.code === 11000) {
      return res.status(409).json({ error: "Email već postoji" });
    }

    return res.status(500).json({ error: "Interna greška servera" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, lozinka } = req.body;

  if (!email || !lozinka) {
    return res.status(400).json({ error: "Email i lozinka su obavezni" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Korisnik ne postoji" });
    }

    const isMatch = await bcrypt.compare(lozinka, user.lozinka);
    if (!isMatch) {
      return res.status(401).json({ error: "Pogrešna lozinka" });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    // Postavljanje tokena u HTTP-only cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Uspešna prijava",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Greška pri loginu:", err);
    res.status(500).json({ error: "Greška na serveru" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  });

  return res.status(200).json({ message: "Uspešno ste se odjavili" });
});


app.get("/api", (req, res) => {
  res.json({ message: "Hello from backend!" });
});


app.listen(PORT, () => {
  console.log(`🚀 Server je pokrenut na portu ${PORT}`);
});
