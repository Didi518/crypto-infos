const express = require("express");
const cookieParser = require("cookie-parser");

const dbConnect = require("./database/index");
const { NODE_ENV, PORT } = require("./config/index");
const router = require("./routes/index");
const errorHandler = require("./middlewares/errorHandler");

const app = express();

app.use(cookieParser());
app.use(express.json());

app.use(router);

dbConnect();

app.use("/uploads", express.static("uploads"));

app.use(errorHandler);

app.listen(
  PORT,
  console.log(`Backend connecté en mode: ${NODE_ENV}, sur le port: ${PORT}`)
);
