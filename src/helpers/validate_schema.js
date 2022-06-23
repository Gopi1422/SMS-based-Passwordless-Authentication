const joi = require("joi");
const logger = require("../config/logger");
const caller = require("./caller");

const authSchema = joi.object({
  name: joi.string().allow(null, ""),
  email: joi.string().required(),
  phone: joi
    .string()
    .regex(/\+91[0-9]{10}$/)
    .messages({ "string.pattern.base": `Phone number must have 10 digits.` })
    .allow(null, "+91"),
  isLogin: joi.boolean(),
});

const registerUserSchema = joi.object({
  name: joi.string().max(100).required(),
  email: joi.string().email().lowercase().required(),
  phone: joi
    .string()
    .regex(/\+91[0-9]{10}$/)
    .messages({ "string.pattern.base": `Phone number must have 10 digits.` })
    .required(),
  isLogin: joi.boolean(),
});

async function validator(validationSchema, req, res) {
  try {
    const result = await validationSchema.validateAsync(req.body);
    // for validation using joi
  } catch (error) {
    logger.warn(` entered invalid data format with respect to fields`);
    caller(req, res, error.message, 400);
    return;
  }
}

module.exports = { authSchema, registerUserSchema, validator };
