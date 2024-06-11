const express = require("express");
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();

const SALT_ROUNDS = 10;

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

const serviceAccount = require('./key.json');
initializeApp({
  credential: cert(serviceAccount)
});

const db = getFirestore();

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

app.get("/", (req, res) => res.redirect("/login"));

app.get("/signup", (req, res) => res.render("signup"));

app.get("/login", (req, res) => res.render("login"));

app.post("/signupSubmit", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await db.collection("users").add({ email, password: hash });
    res.send("Sign up is successful. Go to <a href='/login'>login</a>.");
  } catch (error) {
    console.error("Error during sign up:", error);
    res.status(500).send("Error: Unable to sign up. Please try again later.");
  }
});

app.post("/loginSubmit", async (req, res) => {
  const { email, password } = req.body;
  try {
    const docs = await db.collection("users").where("email", "==", email).get();
    if (docs.size === 0) {
      return res.send("User not found.");
    }
    const user = docs.docs[0].data();
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.user = user;
      res.redirect("/dashboard");
    } else {
      res.send("Incorrect password.");
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).send("Error: Unable to login. Please try again later.");
  }
});

app.get("/dashboard", (req, res) => {
  if (req.session.user) {
    res.render("dashboard");
  } else {
    res.redirect("/login");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Error: Unable to log out. Please try again later.");
    }
    res.redirect("/login");
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
