import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import fs, { existsSync } from "fs";

dotenv.config({ path: ".env" });

const app = express();
const port = process.env.PORT;

app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));

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

app.get("/", (req, res) => {
  const sortedNotes = [...notes].sort((a, b) => {
    const dateA = new Date(a.updatedAt || a.createdAt);
    const dateB = new Date(b.updatedAt || b.createdAt);
    return dateB - dateA;
  });

  res.render("index", { notes: sortedNotes });
});

const now = new Date();

app.post("/post", (req, res) => {
  const content = req.body.post;
  if (content && content.trim() !== "") {
    const newPost = {
      id: notes.length + 1,
      name: "Alfie Agustin",
      content: content,
      createdAt: now,
      updatedAt: now,
    };
    notes.push(newPost);
    saveNotes();
  }
  res.redirect("/");
});

app.post("/delete/:id/", (req, res) => {
  const id = parseInt(req.params.id);
  const searchIdx = notes.findIndex((note) => note.id === id);

  if (searchIdx > -1) {
    notes.splice(searchIdx, 1);
    saveNotes();
  }
  res.redirect("/");
});

app.post("/edit/:id/", (req, res) => {
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
  console.log(`Server running at port http://localhost:${port} `);
});
