import jwt from 'jsonwebtoken';
import { promisify } from 'util';
import User from '../models/User.js';
import AppError from './utils/AppError.js';


/**
 * Authentication middleware that verifies JWT token
 * @param {Array|string} roles - Allowed roles (optional, defaults to all roles)
 * @returns {Function} Express middleware
 */
const authenticate = (roles = []) => {
    // Convert single role to array if needed
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return async (req, res, next) => {
        try {
            // 1) Check if token exists
            let token;

            if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
                token = req.headers.authorization.split(' ')[1];
            } else if (req.cookies && req.cookies.jwt) {
                token = req.cookies.jwt;
            }

            if (!token) {
                return next(new AppError('You are not logged in. Please log in to get access.', 401));
            }

            // 2) Verify token
            const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

            // 3) Check if user still exists
            const user = await User.findById(decoded.sub);
            if (!user) {
                return next(new AppError('The user belonging to this token no longer exists.', 401));
            }

            // 4) Check if user is locked
            if (user.accountLocked) {
                return next(new AppError('This account has been locked. Please reset your password.', 401));
            }

            // 5) Check if token type is 'access'
            if (decoded.type !== 'access') {
                return next(new AppError('Invalid token type. Please use an access token.', 401));
            }

            // 6) Check user role if necessary
            if (roles.length > 0 && !roles.includes(user.role)) {
                return next(new AppError('You do not have permission to perform this action.', 403));
            }

            // 7) Grant access to protected route
            req.user = {
                id: user._id,
                email: user.email,
                role: user.role
            };

            next();
        } catch (error) {
            if (error.name === 'JsonWebTokenError') {
                return next(new AppError('Invalid token. Please log in again.', 401));
            }
            if (error.name === 'TokenExpiredError') {
                return next(new AppError('Your token has expired. Please log in again.', 401));
            }
            next(error);
        }
    };
};

export default authenticate;