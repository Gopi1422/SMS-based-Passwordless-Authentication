const express = require("express");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const userRouter = require("./routes/userRoutes");
const { authenticateUser } = require("./middlewares/authMiddleware");
const cors = require("cors");

const app = express();

dotenv.config();

connectDB();

PORT = process.env.PORT || 5500;

// since we are taking the value from frontend, we need to tell server to accept json data
app.use(express.json());
// app.use(authenticateUser);
// app.use(cors({ origin: "http://localhost" })); // , credentials: true

app.use("/auth", userRouter);

app.get("/", (req, res) => res.send("Hello World!"));
app.listen(PORT, () => console.log(`Example app listening on port ${PORT}!`));

// nginx domain name port path
