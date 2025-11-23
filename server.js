const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const multer = require("multer");
const path = require("path");

const app = express();

/* ===========================
   \u2705 CORS SETUP
=========================== */
app.use(cors({
  origin: "http://localhost:5173",
  methods: ["GET", "POST"],
  credentials: true
}));

app.use(express.json());

// Serve uploaded files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

/* ===========================
   \u2705 DATABASE CONNECTION
=========================== */
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Root@1234",
  database: "chatapp"
});

db.connect(err => {
  if (err) throw err;
  console.log("MySQL Connected");
});

/* ===========================
   \u2705 MULTER SETUP
=========================== */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "_" + file.originalname)
});
const upload = multer({ storage });

/* ===========================
   \u2705 AUTH ROUTES
=========================== */

// Register
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
  db.query(sql, [username, email, hashedPassword], (err, result) => {
    if (err) return res.json({ status: "error", error: err });
    res.json({ status: "success", message: "User registered successfully" });
  });
});

// Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.json({ status: "error", error: err });
    if (!results.length) return res.json({ status: "error", message: "Email not found" });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ status: "error", message: "Incorrect password" });

    const token = jwt.sign({ id: user.id, email: user.email }, "secret123", { expiresIn: "1d" });

    res.json({
      status: "success",
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        profileImage: user.profileImage || "", // ensure frontend can access
        coverImage: user.coverImage || ""
      }
    });
  });
});

/* ===========================
   \u2705 USERS & FRIENDS
=========================== */

// Get all users
app.get("/users", (req, res) => {
  db.query("SELECT id, username, email, profileImage, coverImage FROM users", (err, results) => {
    if (err) return res.json({ status: "error", error: err });
    const users = results.map(u => ({
      ...u,
      profileImage: u.profileImage || "",
      coverImage: u.coverImage || ""
    }));
    res.json({ status: "success", users });
  });
});

// Add friend
app.post("/add-friend", (req, res) => {
  const { userId, friendId } = req.body;

  db.query("SELECT * FROM friends WHERE user_id = ? AND friend_id = ?", [userId, friendId], (err, results) => {
    if (err) return res.json({ status: "error", error: err });
    if (results.length) return res.json({ status: "error", message: "Already friends" });

    db.query("INSERT INTO friends (user_id, friend_id) VALUES (?, ?)", [userId, friendId], (err) => {
      if (err) return res.json({ status: "error", error: err });
      res.json({ status: "success", message: "Friend added successfully" });
    });
  });
});

// Get friends
app.get("/friends/:userId", (req, res) => {
  const userId = Number(req.params.userId);

  const sql = `
    SELECT u.id, u.username, u.email, u.profileImage, u.coverImage
    FROM friends f
    JOIN users u ON f.friend_id = u.id
    WHERE f.user_id = ?
  `;

  db.query(sql, [userId], (err, results) => {
    if (err) return res.json({ status: "error", error: err });
    res.json({ status: "success", friends: results });
  });
});

// Remove friend
app.post("/remove-friend", (req, res) => {
  const { userId, friendId } = req.body;

  if (!userId || !friendId) {
    return res.json({ status: "error", message: "User and friend IDs required" });
  }

  // Delete friendship (both directions for bidirectional friendship)
  const sql = `
    DELETE FROM friends 
    WHERE (user_id = ? AND friend_id = ?) 
       OR (user_id = ? AND friend_id = ?)
  `;
  
  db.query(sql, [userId, friendId, friendId, userId], (err, result) => {
    if (err) {
      console.error("Remove friend error:", err);
      return res.json({ status: "error", error: err });
    }
    
    res.json({ 
      status: "success", 
      message: "Friend removed successfully",
      deletedCount: result.affectedRows
    });
  });
});

/* ===========================
   \u2705 MESSAGES & FILES
=========================== */

// Get messages between two users with sender info
app.get("/messages/:user1/:user2", (req, res) => {
  const { user1, user2 } = req.params;
  const sql = `
    SELECT m.*, u.username AS sender_username, u.profileImage AS sender_profile_image
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
    ORDER BY m.created_at ASC
  `;
  db.query(sql, [user1, user2, user2, user1], (err, results) => {
    if (err) return res.json({ status: "error", error: err });
    res.json({ status: "success", messages: results });
  });
});

// Upload file
app.post("/upload", upload.single("file"), (req, res) => {
  const { senderId, receiverId } = req.body;
  const filePath = `/uploads/${req.file.filename}`;
  const fileType = req.file.mimetype;

  const sql = "INSERT INTO messages (sender_id, receiver_id, message, file_type, file_path) VALUES (?, ?, ?, ?, ?)";
  db.query(sql, [senderId, receiverId, "", fileType, filePath], (err) => {
    if (err) return res.json({ status: "error", error: err });

    const msgData = {
      sender_id: senderId,
      receiver_id: receiverId,
      message: "",
      file_type: fileType,
      file_path: filePath,
      created_at: new Date()
    };

    const roomId = [senderId, receiverId].sort().join("_");
    io.to(roomId).emit("receive_message", msgData);

    res.json({ status: "success", msgData });
  });
});

/* ===========================
   \u2705 PROFILE UPDATE
=========================== */
app.post("/update-profile", upload.fields([
  { name: "profileImage", maxCount: 1 },
  { name: "coverImage", maxCount: 1 }
]), (req, res) => {
  const { userId, username, email } = req.body;
  const fields = [];
  const values = [];

  if (username) { fields.push("username = ?"); values.push(username); }
  if (email) { fields.push("email = ?"); values.push(email); }
  if (req.files?.profileImage) { fields.push("profileImage = ?"); values.push(req.files.profileImage[0].filename); }
  if (req.files?.coverImage) { fields.push("coverImage = ?"); values.push(req.files.coverImage[0].filename); }

  if (!fields.length) return res.json({ status: "error", message: "No data to update" });

  values.push(userId);
  const sql = `UPDATE users SET ${fields.join(", ")} WHERE id = ?`;

  db.query(sql, values, (err) => {
    if (err) return res.json({ status: "error", error: err });

    db.query("SELECT id, username, email, profileImage, coverImage FROM users WHERE id = ?", [userId], (err2, results) => {
      if (err2) return res.json({ status: "error", error: err2 });
      res.json({ status: "success", message: "Profile updated", user: results[0] });
    });
  });
});

/* ===========================
   ✅ MESSAGE DELETION ENDPOINTS
=========================== */

// Delete selected messages - ANY user in conversation can delete
app.post("/delete-messages", (req, res) => {
  const { messageIds, userId, friendId } = req.body;

  if (!messageIds || !Array.isArray(messageIds) || messageIds.length === 0) {
    return res.json({ status: "error", message: "No messages to delete" });
  }

  if (!userId || !friendId) {
    return res.json({ status: "error", message: "User and friend IDs required" });
  }

  // Security: Only allow users to delete messages from their own conversations
  // This means messages where they are either the sender OR receiver
  const sql = `
    DELETE FROM messages 
    WHERE id IN (?) 
    AND (
      (sender_id = ? AND receiver_id = ?) 
      OR (sender_id = ? AND receiver_id = ?)
    )
  `;
  
  db.query(sql, [messageIds, userId, friendId, friendId, userId], (err, result) => {
    if (err) {
      console.error("Delete messages error:", err);
      return res.json({ status: "error", error: err });
    }
    
    res.json({ 
      status: "success", 
      message: "Messages deleted successfully",
      deletedCount: result.affectedRows
    });
  });
});

// Clear entire conversation between two users
app.post("/clear-conversation", (req, res) => {
  const { userId, friendId } = req.body;

  if (!userId || !friendId) {
    return res.json({ status: "error", message: "User IDs required" });
  }

  // Delete all messages between the two users
  const sql = `
    DELETE FROM messages 
    WHERE (sender_id = ? AND receiver_id = ?) 
       OR (sender_id = ? AND receiver_id = ?)
  `;
  
  db.query(sql, [userId, friendId, friendId, userId], (err, result) => {
    if (err) {
      console.error("Clear conversation error:", err);
      return res.json({ status: "error", error: err });
    }
    
    res.json({ 
      status: "success", 
      message: "Conversation cleared successfully",
      deletedCount: result.affectedRows
    });
  });
});

/* ===========================
   ✅ SOCKET.IO (Updated)
=========================== */
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "http://localhost:5173", methods: ["GET", "POST"], credentials: true }
});

let onlineUsers = {};

io.on("connection", socket => {
  console.log("User connected:", socket.id);

  // Track online
  socket.on("user_online", ({ userId }) => {
    onlineUsers[userId] = socket.id;
    io.emit("update_online", Object.keys(onlineUsers));
  });

  // Join room
  socket.on("join_room", ({ roomId }) => socket.join(roomId));

  // Send message
  socket.on("send_message", ({ senderId, receiverId, message }) => {
    const sql = "INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)";
    db.query(sql, [senderId, receiverId, message], (err) => {
      if (err) return console.log(err);
      const msgData = { sender_id: senderId, receiver_id: receiverId, message, created_at: new Date() };
      const roomId = [senderId, receiverId].sort().join("_");
      io.to(roomId).emit("receive_message", msgData);
    });
  });

  // Handle message deletion
  socket.on("messages_deleted", ({ messageIds, roomId }) => {
    io.to(roomId).emit("messages_deleted", { messageIds });
  });

  // Handle conversation cleared
  socket.on("conversation_cleared", ({ roomId }) => {
    io.to(roomId).emit("conversation_cleared");
  });

  // Disconnect
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
    for (const [userId, sId] of Object.entries(onlineUsers)) if (sId === socket.id) delete onlineUsers[userId];
    io.emit("update_online", Object.keys(onlineUsers));
  });
});

/* ===========================
   🚀 START SERVER (IMPORTANT)
=========================== */
const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server + Socket.IO running on port ${PORT}`);
});


