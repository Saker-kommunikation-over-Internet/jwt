import bodyParser from "body-parser";
import express from "express";
import { createClient } from "redis";
import { compareSync } from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const app = express();
//Ansluter till Redis
const redisClient = createClient();
redisClient.connect();

//Sätter upp all nödvändig middleware
app.use(bodyParser.urlencoded({ extended: false }));
//Låter oss läsa cookies från varje request
app.use(cookieParser());

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const dbPassword = await redisClient.get(`user:${username}`);
  //CompareSync hashar det första argumentet och kollar om det blir det andra argumentet.
  if (compareSync(password, dbPassword)) {
    // Om rätt användarnamn och lösenord ges skickar vi en JWT med följande payload.
    const token = jwt.sign(
      { username: username, canViewProtected: true },
      "mySecretKey"
    );
    // Vi säger åt webbläsaren att spara token i en cookie
    res.cookie("token", token);
    res.send("Logged in");
  } else {
    res.status(401).send("Invalid credentials.");
  }
});

app.get("/protected", (req, res, next) => {
  const token = req.cookies.token; //Vi hämtar payload från cookies

  //En invalid token kommer att ge ett error, därför lägger vi den i en try-catch.
  try {
    const payload = jwt.verify(token, "mySecretKey"); // { username: username, canViewProtected: true}
    if (payload.canViewProtected) {
      next();
    } else {
      res.status(401).send("Not permitted.");
    }
  } catch (err) {
    res.send(err);
  }
});

// Den här ska ligga sist. Då körs alla funktioner i respektive get först.
app.use(express.static("public"));

app.listen(8000);
