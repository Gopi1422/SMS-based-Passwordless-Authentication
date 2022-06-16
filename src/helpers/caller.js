function caller(req, res, message, statusCode = 200) {
  // Message = message;

  res.status(statusCode).json(message);
}
module.exports = caller;
