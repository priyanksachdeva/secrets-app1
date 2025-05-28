const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const authMiddleware = require("../middleware/authMiddleware");
const validateEmail = require("../utils/validateEmail");
const validatePassword = require("../utils/validatePassword");

router.get("/", (req, res) => res.redirect("/login"));

router.get("/register", (req, res) => res.render("register"));
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!validateEmail(email))
    return res.render("error", { message: "Invalid email format" });
  if (!validatePassword(password))
    return res.render("error", { message: "Weak password" });

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.create({ name, email, password: hashedPassword });
    res.redirect("/login");
  } catch (err) {
    res.render("error", { message: "User already exists or error" });
  }
});

router.get("/login", (req, res) => res.render("login"));
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.render("error", { message: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.render("error", { message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user._id, name: user.name, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.cookie("token", token, { httpOnly: true, secure: true });
  res.redirect("/secrets");
});

router.get("/secrets", authMiddleware, (req, res) => {
  res.render("secrets", { user: req.user });
});

router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

module.exports = router;
