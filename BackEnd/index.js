require("./passport");
require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const authModel = require("./Models/Model");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const TodoRoutes = require("./Routes/TodoRoutes");
const NoteRoutes = require("./Routes/NoteRoutes");
const TaskRoutes = require("./Routes/TaskRoutes");

const PORT =5000;
// Initialize express app
const app = express();

// Use cors middleware first, before other app.use() configurations
app.use(
  cors({
    origin: process.env.FRONTEND_DOMAIN,
    credentials: true,
    methods: ["GET", "PUT", "PATCH", "PUT", "DELETE"],
  })
);

// Middleware for parsing JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session store
const sessionStore = new MongoStore({
  mongoUrl: process.env.MONGO_URL,
  collectionName: "session",
});

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    store: sessionStore,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
    },
  })
);

// Initialize passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Quotes API
const quotes = [
  {
    content:
      "The only limit to our realization of tomorrow is our doubts of today.",
    author: "Franklin D. Roosevelt",
  },
  {
    content:
      "Do not wait to strike till the iron is hot; but make it hot by striking.",
    author: "William B. Sprague",
  },
  {
    content: "Life is what happens when you're busy making other plans.",
    author: "John Lennon",
  },
];

app.get("/random-quote", (req, res) => {
  const randomQuote = quotes[Math.floor(Math.random() * quotes.length)];
  res.json(randomQuote);
});

// Routes
app.get("/", (req, res) => {
  res.json("Hello");
});

// Register route
app.post("/register", async (req, res) => {
  const { userName, email, password } = req.body;
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  const newAuth = new authModel({
    userName: userName,
    email: email,
    password: hashedPassword,
  });

  try {
    const user = await authModel.findOne({ email: email });
    if (user) res.json("Already Registered");
    else {
      const savedUser = await newAuth.save();
      res.send(savedUser);
    }
  } catch (err) {
    res.status(400).send(err);
  }
});

// Google authentication
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login",
    successRedirect: `http://localhost:3000/home`,
  })
);

// Facebook authentication
app.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);
app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", {
    failureRedirect: "login",
    successRedirect: `http://localhost:3000/home`,
  })
);

// Local Login
app.post("/api/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "An error occurred during login",
      });
    }

    if (!user) {
      // More specific error message based on what failed
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    req.logIn(user, (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Error during login process",
        });
      }

      return res.json({
        success: true,
        message: "Login successful",
      });
    });
  })(req, res, next);
});



// Logout
app.get("/logout", (req, res, next) => {
  req.logOut((err) => {
    if (err) res.send(err);
    else res.json({ success: "logged out" });
  });
});

// Get user data
app.get("/getUser", (req, res, next) => {
  if (req.user) {
    res.json(req.user);
  }
});

// Forgot and reset password
app.post("/resetPassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { newPassword } = req.body;
  jwt.verify(token, process.env.JWT_SECRET_KEY, async (err, encode) => {
    if (err) return res.send({ Status: "Try again after a few minutes" });
    else {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);
      authModel
        .findByIdAndUpdate({ _id: id }, { password: hashedPassword })
        .then(() => res.send({ Status: "success" }))
        .catch((err) => res.send({ Status: err }));
    }
  });
});

app.post("/forgotpass", async (req, res) => {
  const { email } = req.body;
  await authModel.findOne({ email: email }).then((user) => {
    if (!user) return res.send({ Status: "Enter a valid email" });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: "1d",
    });
    var transporter = nodemailer.createTransport({
      service: "gmail",
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: `${process.env.EMAIL_USER}`,
        pass: `${process.env.EMAIL_PASS}`, // Be cautious with hardcoded passwords
      },
    });

    var mailOptions = {
      from: "user-3279a802-637f-4a3f-840f-01290f1b8b1b@mailslurp.biz",
      to: email,
      subject: "Forgot password for task manager",
      text: `${process.env.FRONTEND_DOMAIN}/ResetPass/${user._id}/${token}`,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
      } else {
        return res.send({ Status: "success" });
      }
    });
  });
});

// Authenticator middleware
const authenticator = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Login Required" });
  }
  next();
};

app.use("/todo", [authenticator, TodoRoutes]);
app.use("/note", [authenticator, NoteRoutes]);
app.use("/task", [authenticator, TaskRoutes]);

// Start the server
app.listen(PORT, () => {
  console.log(`Server Running On Port : ${PORT}`);
});

module.exports = app;
