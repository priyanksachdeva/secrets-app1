const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const authMiddleware = require("../middleware/authMiddleware");
const validateEmail = require("../utils/validateEmail");
const validatePassword = require("../utils/validatePassword");

function renderWithUser(res, view, data = {}) {
  return res.render(view, { ...data, user: res.locals.user });
}

router.get("/", (req, res) => res.redirect("/login"));

router.get("/register", (req, res) => {
  renderWithUser(res, "register", { error: null });
});

router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!validateEmail(email)) {
    return renderWithUser(res, "register", {
      error: "Please enter a valid email address.",
    });
  }
  if (!validatePassword(password)) {
    return renderWithUser(res, "register", {
      error:
        "Your password is too weak. Please use at least 8 characters, with uppercase, lowercase, a number, and a special symbol.",
    });
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return renderWithUser(res, "register", {
        error: "That email is already registered. Try logging in instead.",
      });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.create({ name, email, password: hashedPassword });
    res.redirect("/login?registered=1");
  } catch (err) {
    renderWithUser(res, "register", {
      error: "Something went wrong. Please try again.",
    });
  }
});

router.get("/login", (req, res) => {
  const success = req.query.registered
    ? "Registration successful! Please log in."
    : null;
  renderWithUser(res, "login", { error: null, success });
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return renderWithUser(res, "login", {
        error: "Incorrect email or password.",
        success: null,
      });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return renderWithUser(res, "login", {
        error: "Incorrect email or password.",
        success: null,
      });
    }
    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.cookie("token", token, { httpOnly: true, secure: true });
    res.redirect("/secrets");
  } catch (err) {
    renderWithUser(res, "login", {
      error: "Sorry, something went wrong. Please try again.",
      success: null,
    });
  }
});

router.get("/secrets", authMiddleware, (req, res) => {
  renderWithUser(res, "secrets");
});

router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

module.exports = router;
