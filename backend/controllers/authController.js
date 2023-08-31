const Joi = require("joi");
const bcrypt = require("bcryptjs");

const User = require("../models/User");
const RefreshToken = require("../models/Token");
const UserDTO = require("../dto/user");
const JWTService = require("../services/JWTService");

const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,25}$/;

const authController = {
  async register(req, res, next) {
    const userRegisterSchema = Joi.object({
      username: Joi.string().min(5).max(30).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'text'`,
        "string.empty": `{{#label}} ne peut pas rester vide`,
        "string.min": `{{#label}} doit avoir au un minimum de {#limit} caractères`,
        "string.max": `{{#label}} doit avoir au un maximum de {#limit} caractères`,
        "any.required": `{{#label}} est un champ requis`,
      }),
      name: Joi.string().max(30).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'text'`,
        "string.empty": `{{#label}} ne peut pas rester vide`,
        "string.max": `{{#label}} doit avoir au un maximum de {#limit} caractères`,
        "any.required": `{{#label}} est un champ requis`,
      }),
      email: Joi.string().email().required().messages({
        "string.base": `{{#label}} doit être un champ de type 'email'`,
        "string.empty": `{{#label}} ne peut pas rester vide`,
        "any.required": `{{#label}} est un champ requis`,
      }),
      password: Joi.string().pattern(passwordPattern).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'password'`,
        "string.pattern.base":
          "{{#label}} avec la valeur {:[.]} ne correspond pas au pattern: {{#regex}}",
        "any.required": `{{#label}} est un champ requis`,
      }),
      confirmPassword: Joi.any()
        .equal(Joi.ref("password"))
        .required()
        .messages({
          "any.only": "{{#label}} ne correspond pas au mot de passe",
        }),
    });
    const { error } = userRegisterSchema.validate(req.body);
    if (error) {
      return next(error);
    }
    const { username, name, email, password } = req.body;
    try {
      const emailInUse = await User.exists({ email });
      const usernameInUse = await User.exists({ username });
      if (emailInUse) {
        const error = {
          status: 409,
          message: "E-mail déjà enregistrée, utiliser une autre e-mail!",
        };
        return next(error);
      }
      if (usernameInUse) {
        const error = {
          status: 409,
          message: "Pseudonyme indisponible, choissez un autre pseudonyme!",
        };
        return next(error);
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      let accessToken;
      let refreshToken;
      let user;
      try {
        const userToRegister = new User({
          username,
          email,
          name,
          password: hashedPassword,
        });
        user = await userToRegister.save();
        accessToken = JWTService.signAccessToken({ _id: user._id }, "30m");
        refreshToken = JWTService.signRefreshToken({ _id: user._id }, "60m");
      } catch (error) {
        return next(error);
      }
      await JWTService.storeRefreshToken(refreshToken, user._id);
      res.cookie("accessToken", accessToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });
      res.cookie("refreshToken", refreshToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });
      const userDto = new UserDTO(user);
      return res.status(201).json({ user: userDto, auth: true });
    } catch (error) {
      return next(error);
    }
  },

  async login(req, res, next) {
    const userLoginSchema = Joi.object({
      username: Joi.string().min(5).max(30).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'text'`,
        "string.empty": `{{#label}} ne peut pas rester vide`,
        "string.min": `{{#label}} doit avoir au un minimum de {#limit} caractères`,
        "string.max": `{{#label}} doit avoir au un maximum de {#limit} caractères`,
        "any.required": `{{#label}} est un champ requis`,
      }),
      password: Joi.string().pattern(passwordPattern).required().messages({
        "string.base": `{{#label}} doit être un champ de type 'password'`,
        "string.pattern.base":
          "{{#label}} avec la valeur {:[.]} ne correspond pas au pattern: {{#regex}}",
        "any.required": `{{#label}} est un champ requis`,
      }),
    });
    const { error } = userLoginSchema.validate(req.body);
    if (error) {
      return next(error);
    }
    const { username, password } = req.body;
    let user;
    try {
      user = await User.findOne({ username: username });
      if (!user) {
        const error = {
          status: 401,
          message: "Peudonyme incorrect",
        };
        return next(error);
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        const error = {
          status: 401,
          message: "Mot de passe incorrect",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }
    const accessToken = JWTService.signAccessToken({ _id: user._id }, "30m");
    const refreshToken = JWTService.signRefreshToken({ _id: user._id }, "60m");
    try {
      await RefreshToken.updateOne(
        {
          _id: user._id,
        },
        { token: refreshToken },
        { upsert: true }
      );
    } catch (error) {
      return next(error);
    }
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    const userDto = new UserDTO(user);
    return res.status(200).json({ user: userDto, auth: true });
  },

  async logout(req, res, next) {
    const { refreshToken } = req.cookies;
    try {
      await RefreshToken.deleteOne({ token: refreshToken });
    } catch (error) {
      return next(error);
    }
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.status(200).json({ user: null, auth: false });
  },

  async refresh(req, res, next) {
    const originalRefreshToken = req.cookies.refreshToken;
    let id;
    try {
      id = JWTService.verifyRefreshToken(originalRefreshToken)._id;
    } catch (e) {
      const error = {
        status: 401,
        message: "Non autorisé",
      };
      return next(error);
    }
    try {
      const match = RefreshToken.findOne({
        _id: id,
        token: originalRefreshToken,
      });
      if (!match) {
        const error = {
          status: 401,
          message: "Non autorisé",
        };
        return next(error);
      }
    } catch (e) {
      return next(e);
    }
    try {
      const accessToken = JWTService.signAccessToken({ _id: id }, "30m");
      const refreshToken = JWTService.signRefreshToken({ _id: id }, "60m");
      await RefreshToken.updateOne({ _id: id }, { token: refreshToken });
      res.cookie("accessToken", accessToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });
      res.cookie("refreshToken", refreshToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });
    } catch (e) {
      return next(e);
    }
    const user = await User.findOne({ _id: id });
    const userDto = new UserDTO(user);
    return res.status(200).json({ user: userDto, auth: true });
  },
};

module.exports = authController;
