// error.js
const errorHandler = (err, req, res, next) => {
  // Log the error for the developer
  console.error(err.stack);

  // Set a default status code if one isn't already set
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;

  res.status(statusCode).json({
    message: err.message,
    // Only show the error stack in development for security reasons
    stack: process.env.NODE_ENV === 'production' ? '🥞' : err.stack,
  });
};

module.exports = errorHandler;