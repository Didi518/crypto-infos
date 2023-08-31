const Joi = require("joi");
const fs = require("fs");

const Blog = require("../models/Blog");
const { BACKEND_SERVER_PATH } = require("../config/index");
const BlogDTO = require("../dto/blog");
const BlogDetailsDto = require("../dto/blogDetails");
const Comment = require("../models/Comment");

const mongodbIdPattern = /^[0-9a-fA-F]{24}$/;

const blogController = {
  async create(req, res, next) {
    const createBlogSchema = Joi.object({
      title: Joi.string().required().messages({
        "string.base": `{{#label}} doit être un champ de type 'text'`,
        "string.empty": `{{#label}} ne peut pas rester vide`,
        "any.required": `{{#label}} est un champ requis`,
      }),
      author: Joi.string().regex(mongodbIdPattern).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'password'`,
        "string.pattern.base":
          "{{#label}} avec la valeur {:[.]} ne correspond pas au pattern: {{#regex}}",
        "any.required": `{{#label}} est un champ requis`,
      }),
      content: Joi.string().required().messages({
        "string.base": `{{#label}} doit être un champ de type 'text'`,
        "string.empty": `{{#label}} ne peut pas rester vide`,
        "any.required": `{{#label}} est un champ requis`,
      }),
      photo: Joi.string().required().messages({
        "string.base": `{{#label}} doit être un champ de type 'text'`,
        "string.empty": `{{#label}} ne peut pas rester vide`,
        "any.required": `{{#label}} est un champ requis`,
      }),
    });
    const { error } = createBlogSchema.validate(req.body);
    if (error) {
      return next(error);
    }
    const { title, author, content, photo } = req.body;
    const buffer = Buffer.from(
      photo.replace(/^data:image\/(png|jpg|jpeg);base64,/, ""),
      "base64"
    );
    const imagePath = `${Date.now()}-${author}.png`;
    try {
      fs.writeFileSync(`uploads/${imagePath}`, buffer);
    } catch (error) {
      return next(error);
    }
    let newBlog;
    try {
      newBlog = new Blog({
        title,
        author,
        content,
        photoPath: `${BACKEND_SERVER_PATH}/uploads/${imagePath}`,
      });
      await newBlog.save();
    } catch (error) {
      return next(error);
    }
    const blogDto = new BlogDTO(newBlog);
    return res.status(201).json({ blog: blogDto });
  },

  async getAll(req, res, next) {
    try {
      const blogs = await Blog.find({});
      const blogsDto = [];
      for (let i = 0; i < blogs.length; i++) {
        const dto = new BlogDTO(blogs[i]);
        blogsDto.push(dto);
      }
      return res.status(200).json({ blogs: blogsDto });
    } catch (error) {
      return next(error);
    }
  },

  async getById(req, res, next) {
    const getByIdSchema = Joi.object({
      id: Joi.string().regex(mongodbIdPattern).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'password'`,
        "string.pattern.base":
          "{{#label}} avec la valeur {:[.]} ne correspond pas au pattern: {{#regex}}",
        "any.required": `{{#label}} est un champ requis`,
      }),
    });
    const { error } = getByIdSchema.validate(req.params);
    if (error) {
      return next(error);
    }
    let blog;
    const { id } = req.params;
    try {
      blog = await Blog.findOne({ _id: id }).populate("author");
    } catch (error) {
      return next(error);
    }
    const blogDto = new BlogDetailsDto(blog);
    return res.status(200).json({ blog: blogDto });
  },

  async update(req, res, next) {
    const updateBlogSchema = Joi.object({
      title: Joi.string().required().messages({
        "string.base": `{{#label}} doit être un champ de type 'text'`,
        "string.empty": `{{#label}} ne peut pas rester vide`,
        "any.required": `{{#label}} est un champ requis`,
      }),
      content: Joi.string().required().messages({
        "string.base": `{{#label}} doit être un champ de type 'text'`,
        "string.empty": `{{#label}} ne peut pas rester vide`,
        "any.required": `{{#label}} est un champ requis`,
      }),
      author: Joi.string().regex(mongodbIdPattern).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'password'`,
        "string.pattern.base":
          "{{#label}} avec la valeur {:[.]} ne correspond pas au pattern: {{#regex}}",
        "any.required": `{{#label}} est un champ requis`,
      }),
      blogId: Joi.string().regex(mongodbIdPattern).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'password'`,
        "string.pattern.base":
          "{{#label}} avec la valeur {:[.]} ne correspond pas au pattern: {{#regex}}",
        "any.required": `{{#label}} est un champ requis`,
      }),
      photo: Joi.string().messages({
        "string.base": `{{#label}} doit être un champ de type 'text'`,
      }),
    });
    const { error } = updateBlogSchema.validate(req.body);
    if (error) {
      return next(error);
    }
    const { title, content, author, blogId, photo } = req.body;
    let blog;
    try {
      blog = await Blog.findOne({ _id: blogId });
    } catch (error) {
      return next(error);
    }
    if (photo) {
      let previousPhoto = blog.photoPath;
      previousPhoto = previousPhoto.split("/").at(-1);
      fs.unlinkSync(`uploads/${previousPhoto}`);
      const buffer = Buffer.from(
        photo.replace(/^data:image\/(png|jpg|jpeg);base64,/, ""),
        "base64"
      );
      const imagePath = `${Date.now()}-${author}.png`;
      try {
        fs.writeFileSync(`uploads/${imagePath}`, buffer);
      } catch (error) {
        return next(error);
      }
      await Blog.updateOne(
        { _id: blogId },
        {
          title,
          content,
          photoPath: `${BACKEND_SERVER_PATH}/uploads/${imagePath}`,
        }
      );
    } else {
      await Blog.updateOne({ _id: blogId }, { title, content });
    }
    return res.status(200).json({ message: "blog mis à jour!" });
  },

  async delete(req, res, next) {
    const deleteBlogSchema = Joi.object({
      id: Joi.string().regex(mongodbIdPattern).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'password'`,
        "string.pattern.base":
          "{{#label}} avec la valeur {:[.]} ne correspond pas au pattern: {{#regex}}",
        "any.required": `{{#label}} est un champ requis`,
      }),
    });
    const { error } = deleteBlogSchema.validate(req.params);
    if (error) {
      return next(error);
    }
    const { id } = req.params;
    try {
      await Blog.deleteOne({ _id: id });
      await Comment.deleteMany({ blog: id });
    } catch (error) {
      return next(error);
    }
    return res.status(200).json({ message: "blog supprimé" });
  },
};

module.exports = blogController;
