import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

env.config({ path: ".test.env" });

const app = express();
const port = process.env.PORT;
const saltRounds = 10;

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("login");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
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

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
            [username, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/login");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
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
      callbackURL: "http://localhost:3000/auth/google/index",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const email = profile.email;
        const googleId = profile.id;
        let result = await db.query(
          "SELECT * FROM users WHERE google_id = $1",
          [googleId]
        );
        if (result.rows.length === 0) {
          await db.query(
            "INSERT INTO users (username, password, google_id) VALUES ($1, $2, $3)",
            [email, "google", googleId]
          );
          result = await db.query("SELECT * FROM users WHERE google_id = $1", [
            googleId,
          ]);
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

app.post(
  "/post",
  ensureAuthenticated,
  async (req, res) => {
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
  }
);

app.post(
  "/edit/:id/",
  ensureAuthenticated,
  async (req, res) => {
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
  }
);

app.post(
  "/delete/:id/",
  ensureAuthenticated,
  async (req, res) => {
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
  }
);

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

app.listen(port, () => {
  console.log(`Server running at port http://localhost:${port}`);
});
