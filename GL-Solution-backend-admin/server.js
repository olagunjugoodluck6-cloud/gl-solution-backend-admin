require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const multer = require("multer");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD) {
  console.error("Missing SESSION_SECRET or ADMIN_PASSWORD in .env");
  process.exit(1);
}

const dataDir = path.join(__dirname, "data");
const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(dataDir, "gl-solution.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    image TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const existingAdmin = db.prepare("SELECT id FROM admins WHERE username = ?").get("admin");
if (!existingAdmin) {
  const passwordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)")
    .run("admin", passwordHash);
}

app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));

app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(express.json({ limit: "50kb" }));
app.use(express.static(path.join(__dirname, "public"), { index: false }));
app.use("/uploads", express.static(uploadDir, {
  dotfiles: "deny",
  index: false
}));

app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: dataDir }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: "gls.sid",
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 4
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many login attempts. Please wait and try again."
});

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const safeName = `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`;
      cb(null, safeName);
    }
  }),
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const allowed = new Set(["image/jpeg", "image/png", "image/webp"]);
    cb(null, allowed.has(file.mimetype));
  }
});

function requireAdmin(req, res, next) {
  if (req.session.adminId) return next();
  return res.redirect("/admin/login");
}

function cleanText(value, max) {
  return String(value || "").trim().slice(0, max);
}

app.get("/", (req, res) => {
  const posts = db.prepare("SELECT * FROM posts ORDER BY created_at DESC").all();
  res.render("home", {
    posts,
    contact: {
      email: "olagunjugoodluck6@gmail.com",
      phone: "+2349024558208",
      whatsapp: "2349024558208"
    }
  });
});

app.get("/admin/login", (req, res) => {
  if (req.session.adminId) return res.redirect("/admin");
  res.render("login", { error: null });
});

app.post("/admin/login", loginLimiter, (req, res) => {
  const username = cleanText(req.body.username, 50);
  const password = String(req.body.password || "");

  const admin = db.prepare("SELECT * FROM admins WHERE username = ?").get(username);

  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).render("login", { error: "Invalid username or password." });
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).send("Unable to start secure session.");
    req.session.adminId = admin.id;
    req.session.username = admin.username;
    res.redirect("/admin");
  });
});

app.post("/admin/logout", requireAdmin, (req, res) => {
  req.session.destroy(() => res.redirect("/admin/login"));
});

app.get("/admin", requireAdmin, (req, res) => {
  const posts = db.prepare("SELECT * FROM posts ORDER BY created_at DESC").all();
  res.render("admin", { posts, username: req.session.username });
});

app.get("/admin/change-password", requireAdmin, (req, res) => {
  res.render("change-password", { error: null });
});

app.post("/admin/change-password", requireAdmin, (req, res) => {
  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");
  const confirmPassword = String(req.body.confirmPassword || "");

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).send("All password fields are required.");
  }

  if (newPassword.length < 10) {
    return res.status(400).send("New password must be at least 10 characters long.");
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).send("New passwords do not match.");
  }

  const admin = db
    .prepare("SELECT * FROM admins WHERE id = ?")
    .get(req.session.adminId);

  if (!admin || !bcrypt.compareSync(currentPassword, admin.password_hash)) {
    return res.status(401).send("Current password is incorrect.");
  }

  const newPasswordHash = bcrypt.hashSync(newPassword, 12);

  db.prepare("UPDATE admins SET password_hash = ? WHERE id = ?")
    .run(newPasswordHash, req.session.adminId);

  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).send("Password changed, but secure session could not be restarted.");
    }

    req.session.adminId = admin.id;
    req.session.username = admin.username;

    res.redirect("/admin");
  });
});

app.post("/admin/posts", requireAdmin, upload.single("image"), (req, res) => {
  const title = cleanText(req.body.title, 120);
  const body = cleanText(req.body.body, 5000);

  if (!title || !body) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).send("Title and post content are required.");
  }

  const image = req.file ? `/uploads/${path.basename(req.file.path)}` : null;

  db.prepare("INSERT INTO posts (title, body, image) VALUES (?, ?, ?)")
    .run(title, body, image);

  res.redirect("/admin");
});


app.post("/admin/posts/:id/edit", requireAdmin, upload.single("image"), (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).send("Invalid post ID.");
  }

  const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(id);
  if (!post) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(404).send("Post not found.");
  }

  const title = cleanText(req.body.title, 120);
  const body = cleanText(req.body.body, 5000);

  if (!title || !body) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).send("Title and post content are required.");
  }

  let image = post.image;

  if (req.file) {
    image = `/uploads/${path.basename(req.file.path)}`;

    if (post.image) {
      const oldFile = path.join(uploadDir, path.basename(post.image));
      if (fs.existsSync(oldFile)) fs.unlinkSync(oldFile);
    }
  }

  db.prepare(`
    UPDATE posts
    SET title = ?, body = ?, image = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(title, body, image, id);

  res.redirect("/admin");
});

app.post("/admin/posts/:id/delete", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const post = db.prepare("SELECT image FROM posts WHERE id = ?").get(id);

  if (post?.image) {
    const filename = path.basename(post.image);
    const filePath = path.join(uploadDir, filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }

  db.prepare("DELETE FROM posts WHERE id = ?").run(id);
  res.redirect("/admin");
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err?.message === "File too large") {
    return res.status(400).send("Image upload failed. Use JPG, PNG or WebP under 5 MB.");
  }
  console.error(err);
  res.status(500).send("Something went wrong.");
});

app.listen(PORT, () => {
  console.log(`GL Solution running at http://localhost:${PORT}`);
});
