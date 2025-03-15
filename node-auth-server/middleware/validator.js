import { validationResult } from 'express-validator';
import AppError from './utils/AppError.js';

/**
 * Validation middleware that checks for validation errors
 * @param {Array} validations - Array of express-validator validations
 * @returns {Function} Express middleware
 */
export const validate = (validations) => {
    return async (req, res, next) => {
        // Execute all validations
        await Promise.all(validations.map(validation => validation.run(req)));

        // Check if there are validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Format validation errors
            const formattedErrors = errors.array().map(error => ({
                field: error.param,
                message: error.msg
            }));

            // Create error with validation details
            return next(new AppError('Validation failed', 400, true, null, formattedErrors));
        }

        next();
    };
};

export default { validate };