// server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createServer } from "http";
import { Server as SocketIOServer } from "socket.io";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, { cors: { origin: "*" } });

// Resolve __dirname in ESM and setup uploads
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const fname = `${Date.now()}_${Math.random().toString(36).slice(2)}${ext}`;
    cb(null, fname);
  },
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });
app.use("/uploads", express.static(uploadDir));

const { DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, JWT_SECRET, PORT } = process.env;

// Create promise-based MySQL connection
const con = await mysql.createConnection({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
});

console.log("Connected to MySQL");

// Ensure artists.followers column
try {
  await con.query("ALTER TABLE artists ADD COLUMN followers INT NOT NULL DEFAULT 0");
} catch (e) { /* ignore if already exists */ }

// Ensure artist_followers table exists
await con.query(`
  CREATE TABLE IF NOT EXISTS artist_followers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    artist_id INT NOT NULL,
    follower_role ENUM('hirer','artist') NOT NULL,
    follower_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_follow (artist_id, follower_role, follower_id),
    FOREIGN KEY (artist_id) REFERENCES artists(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

// Ensure portfolio_works table exists
await con.query(`
  CREATE TABLE IF NOT EXISTS portfolio_works (
    id INT PRIMARY KEY AUTO_INCREMENT,
    artist_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    work_type VARCHAR(100) NOT NULL,
    description TEXT,
    media_path VARCHAR(500) NOT NULL,
    media_mime VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (artist_id) REFERENCES artists(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

// Ensure artist_profiles table exists
await con.query(`
  CREATE TABLE IF NOT EXISTS artist_profiles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    artist_id INT NOT NULL UNIQUE,
    full_name VARCHAR(255),
    age INT,
    gender VARCHAR(20),
    skills TEXT,
    instagram VARCHAR(255),
    facebook VARCHAR(255),
    youtube VARCHAR(255),
    photo_path VARCHAR(500),
    photo_mime VARCHAR(100),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (artist_id) REFERENCES artists(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

// -------------------- Hirer Signup --------------------
app.post("/api/hirer/signup", async (req, res) => {
  const { fullname, email, password } = req.body;
  if (!fullname || !email || !password)
    return res.status(400).json({ msg: "All fields are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await con.query(
      "INSERT INTO hirers (fullname, email, password) VALUES (?, ?, ?)",
      [fullname, email, hashedPassword]
    );

    res.json({ msg: "Hirer registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------- Hirer Login --------------------
app.post("/api/hirer/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ msg: "Email and password required" });

  try {
    const [rows] = await con.query(
      "SELECT id, email, password, fullname FROM hirers WHERE email = ?",
      [email]
    );
    if (rows.length === 0) return res.status(400).json({ msg: "User not found" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ msg: "Incorrect password" });

    const token = jwt.sign({ id: user.id, role: "hirer" }, JWT_SECRET, { expiresIn: "1h" });

    res.json({
      msg: "Login successful",
      token,
      user: { id: user.id, fullname: user.fullname, email: user.email, role: "hirer" }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------- Artist Signup --------------------
app.post("/api/artist/signup", async (req, res) => {
  const { fullname, email, password } = req.body;
  if (!fullname || !email || !password)
    return res.status(400).json({ msg: "All fields are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await con.query(
      "INSERT INTO artists (fullname, email, password) VALUES (?, ?, ?)",
      [fullname, email, hashedPassword]
    );

    res.json({ msg: "Artist registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------- Artist Login --------------------
app.post("/api/artist/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ msg: "Email and password required" });

  try {
    const [rows] = await con.query(
      "SELECT id, email, password, fullname FROM artists WHERE email = ?",
      [email]
    );
    if (rows.length === 0) return res.status(400).json({ msg: "User not found" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ msg: "Incorrect password" });

    const token = jwt.sign({ id: user.id, role: "artist" }, JWT_SECRET, { expiresIn: "1h" });

    res.json({
      msg: "Login successful",
      token,
      user: { id: user.id, fullname: user.fullname, email: user.email, role: "artist" }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------- Artist Auth + Me Endpoint --------------------
function authArtist(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ msg: "No token provided" });
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "artist") return res.status(403).json({ msg: "Forbidden" });
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ msg: "Invalid token" });
  }
}

function authHirer(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ msg: "No token provided" });
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "hirer") return res.status(403).json({ msg: "Forbidden" });
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ msg: "Invalid token" });
  }
}

function authAny(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ msg: "No token provided" });
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload || !payload.id || !payload.role) return res.status(401).json({ msg: "Invalid token" });
    req.userId = payload.id;
    req.role = payload.role; // 'hirer' or 'artist'
    next();
  } catch (e) {
    return res.status(401).json({ msg: "Invalid token" });
  }
}

app.get("/api/artist/me", authArtist, async (req, res) => {
  try {
    const [rows] = await con.query(
      "SELECT id, fullname, email FROM artists WHERE id = ?",
      [req.userId]
    );
    if (rows.length === 0) return res.status(404).json({ msg: "User not found" });
    return res.json({ user: rows[0] });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------- Portfolio Endpoints --------------------
app.post("/api/artist/portfolio", authArtist, upload.single("file"), async (req, res) => {
  try {
    const { title, workType, description } = req.body;
    if (!title || !workType || !req.file) {
      return res.status(400).json({ msg: "Title, type and file are required" });
    }
    const relPath = `/uploads/${req.file.filename}`;
    const [result] = await con.query(
      "INSERT INTO portfolio_works (artist_id, title, work_type, description, media_path, media_mime) VALUES (?,?,?,?,?,?)",
      [req.userId, title, workType, description || "", relPath, req.file.mimetype]
    );
    const insertId = result.insertId;
    const [rows] = await con.query(
      "SELECT id, artist_id, title, work_type as workType, description, media_path as media_path, media_mime as media_mime, created_at FROM portfolio_works WHERE id = ?",
      [insertId]
    );
    return res.json(rows[0]);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});

app.get("/api/artist/portfolio", authArtist, async (req, res) => {
  try {
    const [rows] = await con.query(
      "SELECT id, artist_id, title, work_type as workType, description, media_path as media_path, media_mime as media_mime, created_at FROM portfolio_works WHERE artist_id = ? ORDER BY created_at DESC",
      [req.userId]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete("/api/artist/portfolio/:id", authArtist, async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await con.query(
      "SELECT id, artist_id, media_path FROM portfolio_works WHERE id = ?",
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ msg: "Not found" });
    const item = rows[0];
    if (item.artist_id !== req.userId) return res.status(403).json({ msg: "Forbidden" });

    await con.query("DELETE FROM portfolio_works WHERE id = ?", [id]);

    // Try to remove file
    if (item.media_path && item.media_path.startsWith("/uploads/")) {
      const abs = path.join(uploadDir, path.basename(item.media_path));
      fs.promises.unlink(abs).catch(() => {});
    }

    return res.json({ msg: "Deleted" });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------- Hirer: Explore Artists --------------------
app.get("/api/hirer/artists", authHirer, async (req, res) => {
  try {
    const [rows] = await con.query(
      `SELECT 
         a.id AS artist_id,
         COALESCE(ap.full_name, a.fullname) AS full_name,
         a.email,
         a.followers,
         ap.age,
         ap.gender,
         ap.skills,
         ap.instagram,
         ap.facebook,
         ap.youtube,
         ap.photo_path,
         ap.photo_mime,
         ap.updated_at,
         (af.artist_id IS NOT NULL) AS followed
       FROM artists a
       LEFT JOIN artist_profiles ap ON ap.artist_id = a.id
       LEFT JOIN artist_followers af ON af.artist_id = a.id AND af.follower_role = 'hirer' AND af.follower_id = ?
       ORDER BY (ap.updated_at IS NULL), ap.updated_at DESC, a.id DESC`,
      [req.userId]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------- Hirer: View Artist Portfolio --------------------
app.get("/api/hirer/portfolio/:artistId", authHirer, async (req, res) => {
  try {
    const artistId = parseInt(req.params.artistId, 10);
    if (!artistId) return res.status(400).json({ msg: "Invalid artist id" });
    const [rows] = await con.query(
      "SELECT id, title, work_type AS workType, description, media_path AS media_path, media_mime AS media_mime, created_at FROM portfolio_works WHERE artist_id = ? ORDER BY created_at DESC",
      [artistId]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------- Artist: Collab (list artists) --------------------
app.get("/api/artist/collab", authArtist, async (req, res) => {
  try {
    const [rows] = await con.query(
      `SELECT 
         ap.artist_id,
         COALESCE(ap.full_name, a.fullname) AS full_name,
         a.email,
         a.followers,
         ap.age,
         ap.gender,
         ap.skills,
         ap.instagram,
         ap.facebook,
         ap.youtube,
         ap.photo_path,
         ap.photo_mime,
         ap.updated_at,
         (af.artist_id IS NOT NULL) AS followed
       FROM artist_profiles ap
       JOIN artists a ON a.id = ap.artist_id
       LEFT JOIN artist_followers af ON af.artist_id = ap.artist_id AND af.follower_role = 'artist' AND af.follower_id = ?
       WHERE ap.artist_id <> ?
       ORDER BY ap.updated_at DESC, ap.artist_id DESC`,
      [req.userId, req.userId]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------- Follow/Unfollow Artist --------------------
app.post("/api/follow/:artistId", authAny, async (req, res) => {
  try {
    const artistId = parseInt(req.params.artistId, 10);
    if (!artistId) return res.status(400).json({ msg: "Invalid artist id" });
    // prevent self-follow if artist
    if (req.role === 'artist' && req.userId === artistId) return res.status(400).json({ msg: "Cannot follow yourself" });

    // ensure artist exists
    const [aRows] = await con.query("SELECT id FROM artists WHERE id = ?", [artistId]);
    if (aRows.length === 0) return res.status(404).json({ msg: "Artist not found" });

    const [ins] = await con.query(
      "INSERT IGNORE INTO artist_followers (artist_id, follower_role, follower_id) VALUES (?,?,?)",
      [artistId, req.role, req.userId]
    );
    if (ins.affectedRows === 1) {
      await con.query("UPDATE artists SET followers = followers + 1 WHERE id = ?", [artistId]);
    }
    const [[c]] = await con.query("SELECT followers FROM artists WHERE id = ?", [artistId]);
    return res.json({ followed: true, followers: c.followers });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete("/api/follow/:artistId", authAny, async (req, res) => {
  try {
    const artistId = parseInt(req.params.artistId, 10);
    if (!artistId) return res.status(400).json({ msg: "Invalid artist id" });

    const [del] = await con.query(
      "DELETE FROM artist_followers WHERE artist_id = ? AND follower_role = ? AND follower_id = ?",
      [artistId, req.role, req.userId]
    );
    if (del.affectedRows === 1) {
      await con.query("UPDATE artists SET followers = GREATEST(followers - 1, 0) WHERE id = ?", [artistId]);
    }
    const [[c]] = await con.query("SELECT followers FROM artists WHERE id = ?", [artistId]);
    return res.json({ followed: false, followers: c.followers });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------- Bookings table --------------------
await con.query(`
  CREATE TABLE IF NOT EXISTS bookings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    hirer_id INT NOT NULL,
    artist_id INT NOT NULL,
    project_title VARCHAR(255) NOT NULL,
    message TEXT,
    booking_date DATETIME NOT NULL,
    status ENUM('pending','accepted','rejected') NOT NULL DEFAULT 'pending',
    payment_status ENUM('pending','paid') NOT NULL DEFAULT 'pending',
    payment_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
    payment_updated_at TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_artist_date (artist_id, booking_date),
    INDEX idx_hirer_date (hirer_id, booking_date),
    FOREIGN KEY (artist_id) REFERENCES artists(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);
// Migrations for existing tables
try { await con.query("ALTER TABLE bookings ADD COLUMN payment_status ENUM('pending','paid') NOT NULL DEFAULT 'pending'"); } catch (e) {}
try { await con.query("ALTER TABLE bookings ADD COLUMN payment_amount DECIMAL(10,2) NOT NULL DEFAULT 0"); } catch (e) {}
try { await con.query("ALTER TABLE bookings ADD COLUMN payment_updated_at TIMESTAMP NULL DEFAULT NULL"); } catch (e) {}

// -------------------- Chat tables --------------------
await con.query(`
  CREATE TABLE IF NOT EXISTS chat_conversations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    key_hash VARCHAR(100) NOT NULL UNIQUE,
    p1_role ENUM('artist','hirer') NOT NULL,
    p1_id INT NOT NULL,
    p2_role ENUM('artist','hirer') NOT NULL,
    p2_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);
await con.query(`
  CREATE TABLE IF NOT EXISTS chat_messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    conversation_id INT NOT NULL,
    sender_role ENUM('artist','hirer') NOT NULL,
    sender_id INT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE,
    INDEX idx_conv_time (conversation_id, created_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

function convKey(roleA, idA, roleB, idB) {
  const a = `${roleA}:${idA}`;
  const b = `${roleB}:${idB}`;
  return a < b ? `${a}|${b}` : `${b}|${a}`;
}

async function getOrCreateConversation(roleA, idA, roleB, idB) {
  const key = convKey(roleA, idA, roleB, idB);
  await con.query(
    "INSERT IGNORE INTO chat_conversations (key_hash, p1_role, p1_id, p2_role, p2_id) VALUES (?,?,?,?,?)",
    [key, roleA, idA, roleB, idB]
  );
  const [[row]] = await con.query("SELECT id, p1_role, p1_id, p2_role, p2_id FROM chat_conversations WHERE key_hash = ?", [key]);
  return row;
}

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;
    if (!token) return next(new Error("No token"));
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = { id: payload.id, role: payload.role };
    return next();
  } catch (e) {
    return next(new Error("Invalid token"));
  }
});

io.on("connection", (socket) => {
  const { id: userId, role } = socket.user;
  socket.join(`user:${role}:${userId}`);

  socket.on("conversation:open", async ({ withRole, withId }) => {
    try {
      const conv = await getOrCreateConversation(role, userId, withRole, withId);
      socket.join(`conv:${conv.id}`);
      const [msgs] = await con.query(
        "SELECT id, sender_role, sender_id, body, created_at FROM chat_messages WHERE conversation_id = ? ORDER BY id ASC LIMIT 100",
        [conv.id]
      );
      socket.emit("conversation:ready", { conversationId: conv.id, messages: msgs });
    } catch (e) {
      socket.emit("error", { msg: e.message || "Failed to open conversation" });
    }
  });

  socket.on("message:send", async ({ conversationId, body }) => {
    if (!body || !conversationId) return;
    try {
      const [ins] = await con.query(
        "INSERT INTO chat_messages (conversation_id, sender_role, sender_id, body) VALUES (?,?,?,?)",
        [conversationId, role, userId, body]
      );
      const msg = { id: ins.insertId, conversationId, sender_role: role, sender_id: userId, body, created_at: new Date() };
      io.to(`conv:${conversationId}`).emit("message:new", msg);
      // notify both participants inbox
      const [[c]] = await con.query("SELECT p1_role,p1_id,p2_role,p2_id FROM chat_conversations WHERE id=?", [conversationId]);
      if (c) {
        io.to(`user:${c.p1_role}:${c.p1_id}`).emit("inbox:update", msg);
        io.to(`user:${c.p2_role}:${c.p2_id}`).emit("inbox:update", msg);
      }
    } catch (e) {
      socket.emit("error", { msg: e.message || "Failed to send message" });
    }
  });
});

// -------------------- Chats list (Artist) --------------------
app.get("/api/artist/chats", authArtist, async (req, res) => {
  try {
    const myId = req.userId;
    const [rows] = await con.query(
      `SELECT 
         c.id AS conversation_id,
         CASE WHEN c.p1_role='artist' AND c.p1_id=? THEN c.p2_role ELSE c.p1_role END AS other_role,
         CASE WHEN c.p1_role='artist' AND c.p1_id=? THEN c.p2_id ELSE c.p1_id END AS other_id,
         (
           CASE WHEN c.p1_role='artist' AND c.p1_id=? THEN 
             (CASE WHEN c.p2_role='artist' 
               THEN (SELECT COALESCE(ap.full_name, a.fullname) FROM artists a LEFT JOIN artist_profiles ap ON ap.artist_id=a.id WHERE a.id=c.p2_id)
               ELSE (SELECT h.fullname FROM hirers h WHERE h.id=c.p2_id) END)
           ELSE 
             (CASE WHEN c.p1_role='artist'
               THEN (SELECT COALESCE(ap.full_name, a.fullname) FROM artists a LEFT JOIN artist_profiles ap ON ap.artist_id=a.id WHERE a.id=c.p1_id)
               ELSE (SELECT h.fullname FROM hirers h WHERE h.id=c.p1_id) END)
           END
         ) AS other_name,
         (SELECT body FROM chat_messages WHERE conversation_id=c.id ORDER BY id DESC LIMIT 1) AS last_body,
         (SELECT created_at FROM chat_messages WHERE conversation_id=c.id ORDER BY id DESC LIMIT 1) AS last_time
       FROM chat_conversations c
       WHERE (c.p1_role='artist' AND c.p1_id=?) OR (c.p2_role='artist' AND c.p2_id=?)
       ORDER BY (last_time IS NULL), last_time DESC`,
      [myId, myId, myId, myId, myId]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------- Bookings Endpoints --------------------
// Hirer creates booking
app.post("/api/hirer/bookings", authHirer, async (req, res) => {
  try {
    const { artistId, projectTitle, message, date } = req.body;
    if (!artistId || !projectTitle || !date) return res.status(400).json({ msg: "artistId, projectTitle, date required" });
    const dt = new Date(date);
    if (isNaN(dt.getTime())) return res.status(400).json({ msg: "Invalid date" });

    const [ins] = await con.query(
      "INSERT INTO bookings (hirer_id, artist_id, project_title, message, booking_date) VALUES (?,?,?,?,?)",
      [req.userId, artistId, projectTitle, message || "", new Date(dt)]
    );
const [[row]] = await con.query(
      "SELECT b.id, b.hirer_id, b.artist_id, b.project_title, b.message, b.booking_date, b.status, b.payment_status, b.payment_amount, b.payment_updated_at, b.created_at, h.fullname AS hirer_name FROM bookings b JOIN hirers h ON h.id=b.hirer_id WHERE b.id=?",
      [ins.insertId]
    );
    // notify artist in realtime
    io.to(`user:artist:${artistId}`).emit("booking:new", row);
    return res.json(row);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Artist: list bookings
app.get("/api/artist/bookings", authArtist, async (req, res) => {
  try {
const [rows] = await con.query(
      "SELECT b.id, b.hirer_id, b.artist_id, b.project_title, b.message, b.booking_date, b.status, b.payment_status, b.payment_amount, b.payment_updated_at, b.created_at, h.fullname AS hirer_name FROM bookings b JOIN hirers h ON h.id=b.hirer_id WHERE b.artist_id = ? ORDER BY b.created_at DESC",
      [req.userId]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Artist: update status
app.patch("/api/artist/bookings/:id", authArtist, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { status } = req.body;
    if (!id || !['accepted','rejected','pending'].includes(status)) return res.status(400).json({ msg: "Invalid" });
    const [[b]] = await con.query("SELECT id, hirer_id, artist_id FROM bookings WHERE id=?", [id]);
    if (!b || b.artist_id !== req.userId) return res.status(404).json({ msg: "Not found" });
    await con.query("UPDATE bookings SET status=? WHERE id=?", [status, id]);
    const [[row]] = await con.query(
      "SELECT b.id, b.hirer_id, b.artist_id, b.project_title, b.message, b.booking_date, b.status, b.payment_status, b.payment_amount, b.payment_updated_at, b.created_at, h.fullname AS hirer_name FROM bookings b JOIN hirers h ON h.id=b.hirer_id WHERE b.id=?",
      [id]
    );
    // notify both sides
    io.to(`user:artist:${row.artist_id}`).emit("booking:update", row);
    io.to(`user:hirer:${row.hirer_id}`).emit("booking:update", row);
    return res.json(row);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Artist: set or update payment amount (quote)
app.patch("/api/artist/bookings/:id/quote", authArtist, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { amount } = req.body;
    if (!id) return res.status(400).json({ msg: 'Invalid id' });
    const amt = amount != null && !isNaN(parseFloat(amount)) ? parseFloat(amount) : null;
    if (amt == null || amt < 0) return res.status(400).json({ msg: 'Invalid amount' });
    const [[b]] = await con.query("SELECT id, hirer_id, artist_id FROM bookings WHERE id=?", [id]);
    if (!b || b.artist_id !== req.userId) return res.status(404).json({ msg: 'Not found' });
    await con.query("UPDATE bookings SET payment_amount=?, payment_status='pending' WHERE id=?", [amt, id]);
    const [[row]] = await con.query(
      "SELECT b.id, b.hirer_id, b.artist_id, b.project_title, b.message, b.booking_date, b.status, b.payment_status, b.payment_amount, b.payment_updated_at, b.created_at, h.fullname AS hirer_name FROM bookings b JOIN hirers h ON h.id=b.hirer_id WHERE b.id=?",
      [id]
    );
    io.to(`user:artist:${row.artist_id}`).emit("booking:update", row);
    io.to(`user:hirer:${row.hirer_id}`).emit("booking:update", row);
    return res.json(row);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Hirer: update payment status
app.patch("/api/hirer/bookings/:id/payment", authHirer, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { status, amount } = req.body; // status 'paid'|'pending'
    if (!id || !['paid','pending'].includes(status)) return res.status(400).json({ msg: 'Invalid' });
    const [[b]] = await con.query("SELECT id, hirer_id, artist_id FROM bookings WHERE id=?", [id]);
    if (!b || b.hirer_id !== req.userId) return res.status(404).json({ msg: 'Not found' });
    const amt = amount != null && !isNaN(parseFloat(amount)) ? parseFloat(amount) : null;
    if (status === 'paid' && (amt == null || amt < 0)) return res.status(400).json({ msg: 'Amount required for paid' });
    await con.query("UPDATE bookings SET payment_status=?, payment_amount=COALESCE(?, payment_amount), payment_updated_at=NOW() WHERE id=?", [status, amt, id]);
    const [[row]] = await con.query(
      `SELECT b.id, b.hirer_id, b.artist_id, b.project_title, b.message, b.booking_date, b.status,
              b.payment_status, b.payment_amount, b.payment_updated_at, b.created_at,
              COALESCE(ap.full_name, a.fullname) AS artist_name
       FROM bookings b
       JOIN artists a ON a.id=b.artist_id
       LEFT JOIN artist_profiles ap ON ap.artist_id=a.id
       WHERE b.id=?`,
      [id]
    );
    io.to(`user:artist:${row.artist_id}`).emit("booking:update", row);
    io.to(`user:hirer:${row.hirer_id}`).emit("booking:update", row);
    return res.json(row);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Hirer: list their bookings
app.get("/api/hirer/bookings", authHirer, async (req, res) => {
  try {
const [rows] = await con.query(
      `SELECT b.id, b.hirer_id, b.artist_id, b.project_title, b.message, b.booking_date, b.status, b.payment_status, b.payment_amount, b.payment_updated_at, b.created_at,
              COALESCE(ap.full_name, a.fullname) AS artist_name
       FROM bookings b
       JOIN artists a ON a.id=b.artist_id
       LEFT JOIN artist_profiles ap ON ap.artist_id=a.id
       WHERE b.hirer_id = ?
       ORDER BY b.created_at DESC`,
      [req.userId]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Hirer: chats list
app.get("/api/hirer/chats", authHirer, async (req, res) => {
  try {
    const myId = req.userId;
    const [rows] = await con.query(
      `SELECT 
         c.id AS conversation_id,
         CASE WHEN c.p1_role='hirer' AND c.p1_id=? THEN c.p2_role ELSE c.p1_role END AS other_role,
         CASE WHEN c.p1_role='hirer' AND c.p1_id=? THEN c.p2_id ELSE c.p1_id END AS other_id,
         (
           CASE WHEN c.p1_role='hirer' AND c.p1_id=? THEN 
             (CASE WHEN c.p2_role='artist' 
               THEN (SELECT COALESCE(ap.full_name, a.fullname) FROM artists a LEFT JOIN artist_profiles ap ON ap.artist_id=a.id WHERE a.id=c.p2_id)
               ELSE (SELECT h.fullname FROM hirers h WHERE h.id=c.p2_id) END)
           ELSE 
             (CASE WHEN c.p1_role='artist'
               THEN (SELECT COALESCE(ap.full_name, a.fullname) FROM artists a LEFT JOIN artist_profiles ap ON ap.artist_id=a.id WHERE a.id=c.p1_id)
               ELSE (SELECT h.fullname FROM hirers h WHERE h.id=c.p1_id) END)
           END
         ) AS other_name,
         (SELECT body FROM chat_messages WHERE conversation_id=c.id ORDER BY id DESC LIMIT 1) AS last_body,
         (SELECT created_at FROM chat_messages WHERE conversation_id=c.id ORDER BY id DESC LIMIT 1) AS last_time
       FROM chat_conversations c
       WHERE (c.p1_role='hirer' AND c.p1_id=?) OR (c.p2_role='hirer' AND c.p2_id=?)
       ORDER BY (last_time IS NULL), last_time DESC`,
      [myId, myId, myId, myId, myId]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------- Artist Profile --------------------
app.get("/api/artist/profile", authArtist, async (req, res) => {
  try {
    const [rows] = await con.query(
      "SELECT artist_id, full_name, age, gender, skills, instagram, facebook, youtube, photo_path, photo_mime, updated_at FROM artist_profiles WHERE artist_id = ?",
      [req.userId]
    );
    if (rows.length === 0) return res.json({});
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.put("/api/artist/profile", authArtist, upload.single("photo"), async (req, res) => {
  try {
    const { full_name, age, gender, skills, instagram, facebook, youtube } = req.body;
    const ageNum = age ? parseInt(age, 10) : null;

    const [rows] = await con.query(
      "SELECT id, photo_path FROM artist_profiles WHERE artist_id = ?",
      [req.userId]
    );

    let photo_path = null;
    let photo_mime = null;
    if (req.file) {
      photo_path = `/uploads/${req.file.filename}`;
      photo_mime = req.file.mimetype;
    }

    if (rows.length === 0) {
      // Insert
      await con.query(
        "INSERT INTO artist_profiles (artist_id, full_name, age, gender, skills, instagram, facebook, youtube, photo_path, photo_mime) VALUES (?,?,?,?,?,?,?,?,?,?)",
        [req.userId, full_name || null, ageNum, gender || null, skills || null, instagram || null, facebook || null, youtube || null, photo_path, photo_mime]
      );
    } else {
      // Update existing
      const existing = rows[0];
      const fields = [full_name || null, ageNum, gender || null, skills || null, instagram || null, facebook || null, youtube || null];
      let sql = "UPDATE artist_profiles SET full_name=?, age=?, gender=?, skills=?, instagram=?, facebook=?, youtube=?";
      const params = [...fields];
      if (photo_path && photo_mime) {
        sql += ", photo_path=?, photo_mime=?";
        params.push(photo_path, photo_mime);
        // Remove old file
        if (existing.photo_path && existing.photo_path.startsWith("/uploads/")) {
          const abs = path.join(uploadDir, path.basename(existing.photo_path));
          fs.promises.unlink(abs).catch(() => {});
        }
      }
      sql += " WHERE artist_id=?";
      params.push(req.userId);
      await con.query(sql, params);
    }

    const [out] = await con.query(
      "SELECT artist_id, full_name, age, gender, skills, instagram, facebook, youtube, photo_path, photo_mime, updated_at FROM artist_profiles WHERE artist_id = ?",
      [req.userId]
    );
    return res.json(out[0] || {});
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});


// 404 JSON fallback (keep at end)
app.use((req, res) => {
  res.status(404).json({ msg: "Not found" });
});

// Global error handler (Multer + general)
app.use((err, req, res, next) => {
  if (err && (err.code === 'LIMIT_FILE_SIZE' || err.name === 'MulterError')) {
    const message = err.code === 'LIMIT_FILE_SIZE' ? 'File too large. Max 50MB.' : err.message;
    return res.status(400).json({ msg: message });
  }
  if (err) {
    console.error('Unhandled error:', err);
    return res.status(500).json({ msg: err.message || 'Server error' });
  }
  next();
});

// -------------------- Start Server --------------------
const port = PORT || 5000;
httpServer.listen(port, () => console.log(`Server running on port ${port}`));
