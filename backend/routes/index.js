const express = require("express");

const authController = require("../controllers/authController");
const auth = require("../middlewares/auth");
const blogController = require("../controllers/blogController");
const commentController = require("../controllers/commentController");

const router = express.Router();

router.post("/api/auth/register", authController.register);
router.post("/api/auth/login", authController.login);
router.post("/api/auth/logout", auth, authController.logout);
router.get("/api/auth/refresh", authController.refresh);

router
  .route("/api/blogs")
  .post(auth, blogController.create)
  .get(auth, blogController.getAll)
  .put(auth, blogController.update);
router
  .route("/api/blogs/:id")
  .get(auth, blogController.getById)
  .delete(auth, blogController.delete);

router.post("/api/comments", auth, commentController.create);
router.get("/api/comments/:id", auth, commentController.getById);

module.exports = router;
