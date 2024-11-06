require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const fs = require("fs");

app.use(express.json());

function readUsers() {
  const data = fs.readFileSync("./database/users.json");
  return JSON.parse(data);
}

let refreshTokens = [];
const users = readUsers();

function generateAccessToken(user) {
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "5m",
  });
  return accessToken;
}

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const user = users.find((user) => user.username === username);
  if (user === null) {
    return res.status(400).send("Cannot find user");
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      // to generate access tokens in env variables used below command
      // require('crypto').randomBytes(64).toString('hex') in node
      const accessToken = generateAccessToken(user);
      const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
      refreshTokens.push(refreshToken);
      res.json({ accessToken, refreshToken, message: "Login success" });
    } else {
      res.status(500).send("Not allowed");
    }
  } catch (e) {
    console.log("Exception in login:: ", e);
    res.sendStatus(500);
  }
});

// generating new token based on refresh token
app.post("/token", (req, res) => {
  const token = req.body.token;
  if (token === null) return res.sendStatus(401);
  if (!refreshTokens.includes(token)) return res.sendStatus(403);
  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    const accessToken = generateAccessToken({ name: user.name });
    res.json(accessToken);
  });
});

// de-authenticating refresh tokens
app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter(
    (refreshToken) => refreshToken !== req.body.token
  );
  res.sendStatus(204);
});

app.listen(4000, () => {
  console.log("authServer at 4000");
});
