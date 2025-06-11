import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import multer from "multer";
import path from "path";

env.config({ path: ".env" });

const app = express();
const port = process.env.PORT;
const saltRounds = 10;

// Database setup
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Middleware setup
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());
app.set("view engine", "ejs");

// Routes
app.get("/", (req, res) => res.render("login"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/index", (req, res) => {
  if (req.isAuthenticated()) {
    db.query(
      "SELECT * FROM notes WHERE username = $1 ORDER BY updated_at DESC",
      [req.user.username]
    ).then((result) => {
      res.render("index", { notes: result.rows, user: req.user });
    });
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/index",
  passport.authenticate("google", {
    successRedirect: "/index",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/index",
    failureRedirect: "/login",
  })
);

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: "public/uploads/",
  filename: function (req, file, cb) {
    cb(null, 'avatar-' + Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 1000000 }, // 1MB limit
  fileFilter: function (req, file, cb) {
    checkFileType(file, cb);
  }
});

// Check file type
function checkFileType(file, cb) {
  const filetypes = /jpeg|jpg|png|gif/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb('Error: Images Only!');
  }
}

// Update the register route to handle file upload
app.post("/register", upload.single('avatar'), async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const avatarPath = req.file ? `/uploads/${req.file.filename}` : '/assets/avatar.jpg';

  try {
    const checkResult = await db.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.redirect("/register");
        } else {
          const result = await db.query(
            "INSERT INTO users (username, password, profile_picture) VALUES ($1, $2, $3) RETURNING *",
            [username, hash, avatarPath]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error("Login error:", err);
              return res.redirect("/register");
            }
            res.redirect("/index");
          });
        }
      });
    }
  } catch (err) {
    console.error("Registration error:", err);
    res.redirect("/register");
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE username = $1 ",
        [username]
      );
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://notes-2ix1.onrender.com/auth/google/index",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const { email, id: googleId, picture } = profile;
        const profilePicture = picture || profile.photos?.[0]?.value;

        let result = await db.query("SELECT * FROM users WHERE google_id = $1", [
          googleId,
        ]);

        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (username, password, google_id, profile_picture) VALUES ($1, $2, $3, $4) RETURNING *",
            [email, "google", googleId, profilePicture]
          );
          result = { rows: [newUser.rows[0]] };
        }

        return cb(null, result.rows[0]);
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user.username);
});

passport.deserializeUser(async (username, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});

app.post("/post", ensureAuthenticated, async (req, res) => {
  const content = req.body.post?.trim();
  if (content) {
    try {
      await db.query("INSERT INTO notes (username, content) VALUES($1, $2)", [
        req.user.username,
        content,
      ]);
    } catch (err) {
      console.error("Error Posting Note:", err);
    }
  }
  res.redirect("/index");
});

app.post("/edit/:id/", ensureAuthenticated, async (req, res) => {
  const id = Number(req.params.id);
  const updatedContent = req.body.content;

  try {
    await db.query(
      "UPDATE notes SET content = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND username = $3",
      [updatedContent, id, req.user.username]
    );
  } catch (err) {
    console.error("Error Updating Note:", err);
  }
  res.redirect("/index");
});

app.post("/delete/:id/", ensureAuthenticated, async (req, res) => {
  const id = Number(req.params.id);
  try {
    await db.query("DELETE FROM notes WHERE id = $1 AND username = $2", [
      id,
      req.user.username,
    ]);
  } catch (err) {
    console.error("Error Deleting Post", err);
  }
  res.redirect("/index");
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

app.listen(port, () => {
  console.log(`Server running at port http://localhost:${port}`);
});
