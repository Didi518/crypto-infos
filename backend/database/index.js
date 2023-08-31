const mongoose = require("mongoose");
const { MONGODB_CONNEXION_STRING } = require("../config/index");

const dbConnect = async () => {
  try {
    mongoose.set("strictQuery", false);
    const conn = await mongoose.connect(MONGODB_CONNEXION_STRING);
    console.log(
      `Base de données connectée sur l'hôte: ${conn.connection.host}`
    );
  } catch (error) {
    console.log(`Erreur: ${error}`);
  }
};

module.exports = dbConnect;
