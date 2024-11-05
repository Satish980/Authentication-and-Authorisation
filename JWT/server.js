require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

app.use(express.json());

const posts = [
  {
    username: "Satish",
    title: "Post 1",
  },
  {
    username: "Kiran",
    title: "Post 2",
  },
];

app.get("/posts", authenticateToken, (req, res) => {
  return res.json(posts.filter((post) => post.username === req.user.name));
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
