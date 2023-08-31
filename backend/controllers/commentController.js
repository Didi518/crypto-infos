const Joi = require("joi");

const Comment = require("../models/Comment");
const CommentDTO = require("../dto/comment");

const mongodbIdPattern = /^[0-9a-fA-F]{24}$/;

const commentController = {
  async create(req, res, next) {
    const createCommentSchema = Joi.object({
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
      blog: Joi.string().regex(mongodbIdPattern).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'password'`,
        "string.pattern.base":
          "{{#label}} avec la valeur {:[.]} ne correspond pas au pattern: {{#regex}}",
        "any.required": `{{#label}} est un champ requis`,
      }),
    });
    const { error } = createCommentSchema.validate(req.body);
    if (error) {
      return next(error);
    }
    const { content, author, blog } = req.body;
    try {
      const newComment = new Comment({
        content,
        author,
        blog,
      });
      await newComment.save();
    } catch (error) {
      return next(error);
    }
    return res.status(201).json({ message: "commentaire créé" });
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
    const { id } = req.params;
    let comments;
    try {
      comments = await Comment.find({ blog: id }).populate("author");
    } catch (error) {
      return next(error);
    }
    let commentsDto = [];
    for (let i = 0; i < comments.length; i++) {
      const obj = new CommentDTO(comments[i]);
      commentsDto.push(obj);
    }
    return res.status(200).json({ data: commentsDto });
  },
};

module.exports = commentController;
