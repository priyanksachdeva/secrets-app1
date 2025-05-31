const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const authMiddleware = require("../middleware/authMiddleware");
const validateEmail = require("../utils/validateEmail");
const validatePassword = require("../utils/validatePassword");

// Helper function to get user from res.locals in each route
function getUser(req) {
  return req.app.locals.user || null;
}

// Helper to pass user from res.locals.user to templates
function renderWithUser(res, view, data = {}) {
  return res.render(view, { ...data, user: res.locals.user });
}

router.get("/", (req, res) => res.redirect("/login"));

// Register routes
router.get("/register", (req, res) => {
  renderWithUser(res, "register");
});

router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!validateEmail(email))
    return res.render("register", { user: null, error: "Invalid email format" });
  if (!validatePassword(password))
    return res.render("register", { user: null, error: "Weak password" });

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.create({ name, email, password: hashedPassword });
    res.redirect("/login");
  } catch (err) {
    res.render("register", { user: null, error: "User already exists or error" });
  }
});

// Login routes
router.get("/login", (req, res) => {
  res.render("login", { user: null, error: null });
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render("login", { user: null, error: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("login", { user: null, error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, { httpOnly: true, secure: true });
    res.redirect("/secrets");

  } catch (err) {
    console.error(err);
    res.render("login", { user: null, error: "An error occurred. Please try again." });
  }
});

// Secrets (protected)
router.get("/secrets", authMiddleware, (req, res) => {
  renderWithUser(res, "secrets");
});

// Logout route
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

module.exports = router;
