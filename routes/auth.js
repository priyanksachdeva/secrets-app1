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
  return req.app.locals.user || null; // fallback if you want to store it globally
}

// Alternatively, pass user explicitly from res.locals.user to templates:
function renderWithUser(res, view, data = {}) {
  // Add user from res.locals.user to the data object for EJS templates
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
    return renderWithUser(res, "error", { message: "Invalid email format" });
  if (!validatePassword(password))
    return renderWithUser(res, "error", { message: "Weak password" });

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.create({ name, email, password: hashedPassword });
    res.redirect("/login");
  } catch (err) {
    renderWithUser(res, "error", { message: "User already exists or error" });
  }
});

// Login routes
router.get("/login", (req, res) => {
  renderWithUser(res, "login");
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return renderWithUser(res, "error", { message: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return renderWithUser(res, "error", { message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user._id, name: user.name, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.cookie("token", token, { httpOnly: true, secure: true });
  res.redirect("/secrets");
});

// Secrets (protected)
router.get("/secrets", authMiddleware, (req, res) => {
  // You can rely on user from res.locals.user, but passing explicitly is fine
  renderWithUser(res, "secrets");
});

// Logout route
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

module.exports = router;
