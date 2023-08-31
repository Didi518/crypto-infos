require("dotenv").config();

const NODE_ENV = process.env.NODE_ENV;
const PORT = process.env.PORT || 8000;
const MONGODB_CONNEXION_STRING = process.env.MONGO_URI.replace(
  "<password>",
  process.env.MONGO_PASS
);
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const BACKEND_SERVER_PATH = process.env.BACKEND_SERVER_PATH;

module.exports = {
  ACCESS_TOKEN_SECRET,
  BACKEND_SERVER_PATH,
  MONGODB_CONNEXION_STRING,
  NODE_ENV,
  PORT,
  REFRESH_TOKEN_SECRET,
};
