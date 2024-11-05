require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

app.use(express.json());

let refreshTokens = [];

function generateAccessToken(user) {
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15s",
  });
  return accessToken;
}

app.post("/login", (req, res) => {
  const username = req.body.username;
  const user = { name: username };

  // to generate access tokens in env variables used below command
  // require('crypto').randomBytes(64).toString('hex') in node
  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  refreshTokens.push(refreshToken);
  res.json({ accessToken, refreshToken });
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
