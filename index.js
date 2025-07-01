require("dotenv").config();
const User = require("./models/User");
const express = require("express");
const connectDB = require("./db.js");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

const allowedOrigins = [
  "http://localhost:3000",
  "https://docora.rs",
  "https://www.docora.rs",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (origin && !allowedOrigins.includes(origin)) {
        return callback(new Error("CORS policy: Origin not allowed"), false);
      }
      return callback(null, true);
    },
    credentials: true,
  })
);
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

    // 🔐 Kreiranje aktivacionog tokena
    const activationToken = crypto.randomBytes(32).toString("hex");
    const activationTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24h

    const newUser = new User({
      name,
      email,
      lozinka: hashedPassword,
      delatnost,
      adresa,
      isActive: false, // korisnik nije aktivan dok ne klikne link
      activationToken,
      activationTokenExpires,
    });

    await newUser.save();

    // 📧 Slanje aktivacionog emaila
    const transporterOptions = {
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    };

    if (process.env.NODE_ENV === "development") {
      transporterOptions.tls = {
        rejectUnauthorized: false,
      };
    }

    const transporter = nodemailer.createTransport(transporterOptions);

    const activationLink = `https://docora.rs/api/activate/${activationToken}`;

    await transporter.sendMail({
      from: `"Docora" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: "Aktivacija naloga",
      html: `
        <h2>Zdravo ${name},</h2>
        <p>Hvala što ste se registrovali! Kliknite na link ispod da aktivirate svoj nalog:</p>
        <a href="${activationLink}">${activationLink}</a>
        <p>Link važi 24h.</p>
      `,
    });

    return res.status(201).json({
      message: "Registracija uspešna! Proverite email za aktivaciju.",
    });
  } catch (err) {
    console.error("Greška pri registraciji:", err);
    return res.status(500).json({ error: "Greška na serveru" });
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

    if (!user.isActive) {
      return res.status(403).json({
        error: "Nalog nije aktiviran. Proverite email za aktivaciju.",
      });
    }

    const isMatch = await bcrypt.compare(lozinka, user.lozinka);
    if (!isMatch) {
      return res.status(401).json({ error: "Pogrešna lozinka" });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "30d",
    });

    // Postavljanje tokena u HTTP-only cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
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

app.get("/api/activate/:token", async (req, res) => {
  const { token } = req.params;

  try {
    const user = await User.findOne({
      activationToken: token,
      activationTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .send("Link za aktivaciju je nevažeći ili je istekao.");
    }

    user.isActive = true;
    user.activationToken = undefined;
    user.activationTokenExpires = undefined;
    await user.save();

    return res.send(`
      <html>
        <head>
          <title>Nalog aktiviran</title>
          <meta charset="UTF-8" />
          <style>
            body { font-family: sans-serif; text-align: center; margin-top: 50px; }
            .container { padding: 30px; border: 1px solid #ccc; border-radius: 8px; display: inline-block; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>✅ Uspešna aktivacija</h2>
            <p>Vaš nalog je uspešno aktiviran.</p>
            <a href="https://docora.rs/login">Kliknite ovde da se prijavite</a>
          </div>
        </body>
      </html>
    `);
  } catch (err) {
    console.error("Greška pri aktivaciji:", err);
    return res.status(500).send("Greška na serveru prilikom aktivacije.");
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server je pokrenut na portu ${PORT}`);
});
