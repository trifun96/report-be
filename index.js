require("dotenv").config();
const User = require("./models/User");
const express = require("express");
const connectDB = require("./db.js");
const bcrypt = require("bcrypt");
const cors = require("cors");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const { Resend } = require("resend");
const OpenAI = require("openai");
const rateLimit = require('express-rate-limit');
const multer = require("multer");

const openai = new OpenAI({
  apiKey: process.env.REACT_APP_OPENAI_API_KEY,
});

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

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Previše pokušaja registracije, pokušajte kasnije.",
});

const upload = multer();

app.post("/api/register", registerLimiter, async (req, res) => {
  const { name, email, lozinka, delatnost, adresa } = req.body;

  // Provera da li su sva polja popunjena
  if (!name || !email || !lozinka || !delatnost || !adresa) {
    return res.status(400).json({ error: "Sva polja su obavezna" });
  }

  try {
    // Provera da li korisnik već postoji
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: "Korisnik već postoji" });
    }

    // Hash lozinke
    const hashedPassword = await bcrypt.hash(lozinka, 10);

    // Kreiranje aktivacionog tokena
    const activationToken = crypto.randomBytes(32).toString("hex");
    const activationTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24h od sada

    // Kreiranje novog korisnika (neaktivan)
    const newUser = new User({
      name,
      email,
      lozinka: hashedPassword,
      delatnost,
      adresa,
      isActive: false,
      activationToken,
      activationTokenExpires,
    });

    await newUser.save();

    const resend = new Resend(process.env.RESEND_API_KEY);

    const activationLink = `https://docora.rs/api/activate/${activationToken}`;

    // Slanje mejla
    await resend.emails.send({
    from: "Docora <noreply@docora.rs>",
      to: email,
      subject: "Aktivacija naloga",
      html: `
        <h2>Zdravo ${name},</h2>
        <p>Hvala što ste se registrovali! Kliknite na link ispod da aktivirate svoj nalog:</p>
        <a href="${activationLink}">${activationLink}</a>
        <p>Link važi 24h.</p>
      `,
    });

    // Vraćanje uspeha
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

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Uspešna prijava",
      user: {
        name: user.name,
        email: user.email,
        delatnost:user.delatnost
      },
    });
  } catch (err) {
    console.error("Greška pri loginu:", err);
    res.status(500).json({ error: "Greška na serveru" });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email je obavezan." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Korisnik ne postoji." });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpires = Date.now() + 3600000; // 1h

    user.resetToken = resetToken;
    user.resetTokenExpires = resetTokenExpires;
    await user.save();

    const resend = new Resend(process.env.RESEND_API_KEY);
    const resetLink = `https://docora.rs/reset-password/${resetToken}`;

    await resend.emails.send({
      from: "Docora <noreply@docora.rs>",
      to: email,
      subject: "Resetovanje lozinke",
      html: `
        <p>Zahtevali ste promenu lozinke.</p>
        <p>Kliknite na link ispod da postavite novu lozinku:</p>
        <a href="${resetLink}">${resetLink}</a>
        <p>Link važi 1 sat.</p>
      `,
    });

    return res.status(200).json({ message: "Link za reset lozinke je poslat na email." });
  } catch (err) {
    console.error("Greška:", err);
    return res.status(500).json({ error: "Greška na serveru" });
  }
});


app.post("/api/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { lozinka } = req.body;

  if (!lozinka) {
    return res.status(400).json({ error: "Nova lozinka je obavezna." });
  }

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: "Token je nevažeći ili je istekao." });
    }

    user.lozinka = await bcrypt.hash(lozinka, 10);
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;
    await user.save();

    return res.status(200).json({ message: "Lozinka je uspešno resetovana." });
  } catch (err) {
    console.error("Greška:", err);
    return res.status(500).json({ error: "Greška na serveru" });
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

app.post("/api/send-report", upload.single("pdf"), async (req, res) => {
  const { email } = req.body;
  const pdfBuffer = req.file?.buffer;

  if (!email || !pdfBuffer) {
    return res.status(400).send("Nedostaju podaci");
  }

  try {
    const resend = new Resend(process.env.RESEND_API_KEY);

    // Konvertovanje PDF u Base64 string
    const base64PDF = pdfBuffer.toString("base64");

    await resend.emails.send({
      from: "Docora <noreply@docora.rs>",
      to: email,
      subject: "Medicinski izveštaj",
      html: `
        <p>Poštovani,</p>
        <p>U prilogu se nalazi Vaš medicinski izveštaj.</p>
        <p>Srdačno,<br/>Docora tim</p>
      `,
      attachments: [
        {
          filename: "izvestaj.pdf",
          content: base64PDF,
          type: "application/pdf",
        },
      ],
    });

    return res.send("Mejl uspešno poslat");
  } catch (error) {
    console.error("Greška pri slanju mejla (Resend):", error);
    return res.status(500).send("Greška pri slanju mejla");
  }
});
app.post("/api/generate-report", async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Niste prijavljeni." });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    const isUnlimitedUser = user.email === "samsungtrifke@gmail.com";

    if (!isUnlimitedUser) {
      if (user.subscriptionExpires && user.subscriptionExpires < new Date()) {
        user.isSubscribed = false;
        await user.save();
      }

      if (!user.isSubscribed) {
        if (user.reportCredits <= 0) {
          return res.status(403).json({
            error: "Iskoristili ste sve besplatne izveštaje.",
            upgrade: true,
          });
        }

        user.reportCredits -= 1;

        if (user.reportCredits === 0) {
          const resend = new Resend(process.env.RESEND_API_KEY);
          await resend.emails.send({
            from: "Docora <noreply@docora.rs>",
            to: user.email,
            subject: "Iskoristili ste sve besplatne izveštaje",
            html: `
              <p>Poštovani,</p>
              <p>Iskoristili ste sve besplatne izveštaje.</p>
              <p>Da biste nastavili sa korišćenjem aplikacije, izaberite jedan od planova:</p>
              <a href="https://docora.rs/subscribe">Pogledaj pretplate</a>
            `,
          });
        }

        await user.save();
      }
    }

    const prompt = req.body.prompt;
    if (!prompt || prompt.trim().length < 10) {
      return res.status(400).json({ error: "Prompt nije validan ili je prekratak." });
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: "Ti si lekar koji piše medicinski izveštaj na osnovu diktata." },
        { role: "user", content: prompt },
      ],
      temperature: 0.2,
    });

    const report = completion.choices[0].message.content;
    res.json({ report });
  } catch (error) {
    console.error("Greška u /api/generate-report:", error);
    res.status(500).json({ error: "Greška pri generisanju izveštaja." });
  }
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

app.post("/api/contact", async (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ error: "Sva polja su obavezna." });
  }

  try {
    const resend = new Resend(process.env.RESEND_API_KEY);

await resend.emails.send({
  from: "Docora <noreply@docora.rs>",
  to: "samsungtrifke@gmail.com",
  replyTo: email,
  subject: `Nova poruka sa kontakt forme`,
  html: `
    <h3>Nova poruka</h3>
    <p><strong>Ime:</strong> ${name}</p>
    <p><strong>Email:</strong> ${email}</p>
    <p><strong>Poruka:</strong></p>
    <p>${message.replace(/\n/g, "<br>")}</p>
  `,
});

    return res.status(200).json({ message: "Poruka uspešno poslata." });
  } catch (error) {
    console.error("Greška pri slanju kontakt poruke:", error);
    return res.status(500).json({ error: "Greška pri slanju poruke." });
  }
});


app.listen(PORT, () => {
  console.log(`🚀 Server je pokrenut na portu ${PORT}`);
});
