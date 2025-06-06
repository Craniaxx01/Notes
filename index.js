import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import fs from "fs";
import pg from "pg";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";

dotenv.config({ path: ".env" });

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));

app.use(cookieParser(process.env.SECRET));

const saltRounds = 10;

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  ssl: { rejectUnauthorized: false }, 
});
db.connect();

function noCache(req, res, next) {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  next();
}

let notes = [];
const notesFile = "./notes.json";

if (fs.existsSync(notesFile)) {
  const data = fs.readFileSync(notesFile, "utf-8");
  try {
    notes = JSON.parse(data).map((note) => {
      const timestamp = note.timestamp || new Date();
      return {
        ...note,
        createdAt: note.createdAt || timestamp,
        updatedAt: note.updatedAt || timestamp,
      };
    });
  } catch (err) {
    notes = [];
  }
}

function saveNotes() {
  fs.writeFileSync(notesFile, JSON.stringify(notes, null, 2), "utf-8");
}

function isAuthenticated(req, res, next) {
  if (req.signedCookies.username) return next();
  res.redirect("/login");
}

app.get("/", isAuthenticated, noCache, (req, res) => {
  if (!req.signedCookies.username) return res.redirect("/login");

  const sortedNotes = [...notes].sort((a, b) => {
    const dateA = new Date(a.updatedAt || a.createdAt);
    const dateB = new Date(b.updatedAt || b.createdAt);
    return dateB - dateA;
  });

  res.render("index", {
    notes: sortedNotes,
    user: { username: req.signedCookies.username },
  });
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const userExists = await db.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (userExists.rows.length > 0) {
      return res.render("register", { error: "Username already exists" });
    }

    const hash = await bcrypt.hash(password, saltRounds);
    await db.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
      username,
      hash,
    ]);

    res.redirect("/login");
  } catch (err) {
    console.error("Registration error:", err);
    res.render("register", { error: "Registration failed" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (result.rows.length === 0) {
      return res.render("login", { error: "User not found" });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      res.cookie("username", user.username, {
        signed: true,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        secure: process.env.NODE_ENV === "production",
      });
      res.redirect("/");
    } else {
      res.render("login", { error: "Incorrect password" });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.render("login", { error: "Login failed" });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("username", { signed: true });
  res.redirect("/login");
});

// Post a note
app.post("/post", isAuthenticated, (req, res) => {
  const content = req.body.post;
  if (content && content.trim() !== "") {
    const newPost = {
      id: notes.length + 1,
      name: req.signedCookies.username,
      content: content,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    notes.push(newPost);
    saveNotes();
  }
  res.redirect("/");
});

// Delete a note
app.post("/delete/:id/", isAuthenticated, (req, res) => {
  const id = parseInt(req.params.id);
  const searchIdx = notes.findIndex((note) => note.id === id);

  if (searchIdx > -1) {
    notes.splice(searchIdx, 1);
    saveNotes();
  }
  res.redirect("/");
});

// Edit a note
app.post("/edit/:id/", isAuthenticated, (req, res) => {
  const id = parseInt(req.params.id);
  const updatedContent = req.body.content;

  const note = notes.find((note) => note.id === id);
  if (note && updatedContent.trim() !== "") {
    note.content = updatedContent;
    note.updatedAt = new Date();
    saveNotes();
  }
  res.redirect("/");
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
