require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const fs = require('fs');

app.use(express.json());

function readPosts() {
  const data = fs.readFileSync('./database/posts.json');
  return JSON.parse(data);
}

function writePosts(posts) {
  fs.writeFileSync('./database/posts.json', JSON.stringify(posts))
}

const posts = readPosts();

function readUsers() {
  const data = fs.readFileSync('./database/users.json');
  return JSON.parse(data);
}

function writeUsers(users) {
  fs.writeFileSync('./database/users.json', JSON.stringify(users))
}

const users = readUsers();

app.get("/posts", authenticateToken, (req, res) => {
  return res.json(posts.filter((post) => post.username === req.user.username));
});

app.post("/create-user", async (req, res) => {
  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    // we can do above 2 steps in one line
    // const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { username: req.body.username, password: hashedPassword };
    users.push(user);
    writeUsers(users);
    res.status(201).send("User creation success");
  } catch (e) {
    res.sendStatus(500);
  }
});

// middleware function to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];
  if (token === null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

app.listen(3000, () => {
  console.log("Server at 3000");
});
