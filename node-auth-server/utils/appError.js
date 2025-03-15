/**
 * Custom application error class to standardize error handling
 * @extends Error
 */
class AppError extends Error {
    /**
     * Create a new AppError
     * @param {string} message - Error message
     * @param {number} statusCode - HTTP status code
     * @param {boolean} isOperational - Is this an operational error (vs programming error)
     * @param {string} stack - Error stack trace
     */
    constructor(message, statusCode, isOperational = true, stack = '') {
      super(message);
      this.statusCode = statusCode;
      this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
      this.isOperational = isOperational;
      
      if (stack) {
        this.stack = stack;
      } else {
        Error.captureStackTrace(this, this.constructor);
      }
    }
  }
  
  export default AppError;