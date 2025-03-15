import AppError from '../utils/appError.js';
import globalErrorHandler from '../controllers/error.js';

/**
 * Set up global error handling middleware
 * @param {Object} app - Express application instance
 */
const setupGlobalErrorHandling = (app) => {
  console.log("Setting up global error handler middleware");

  // Handle 404 - routes that don't exist
  app.all("*", (req, res, next) => {
    console.log(`Route not found: ${req.originalUrl}`);
    next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
  });

  // Apply global error handler
  app.use(globalErrorHandler);

  console.log("Global error handler middleware setup complete");
};

export default setupGlobalErrorHandling;