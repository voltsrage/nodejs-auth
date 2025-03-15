import { body, param } from 'express-validator';

// Authentication validations
export const authValidation = {
    // Register validation
    register: [
        body('email')
            .isEmail()
            .withMessage('Please provide a valid email address')
            .normalizeEmail(),
        body('password')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters long')
            .matches(/\d/)
            .withMessage('Password must contain at least one number')
            .matches(/[a-zA-Z]/)
            .withMessage('Password must contain at least one letter'),
        body('username')
            .isLength({ min: 3 })
            .withMessage('Username must be at least 3 characters long')
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username can only contain letters, numbers, and underscores'),
        body('firstName')
            .optional()
            .isLength({ min: 1 })
            .withMessage('First name cannot be empty'),
        body('lastName')
            .optional()
            .isLength({ min: 1 })
            .withMessage('Last name cannot be empty'),
        body('phoneNumber')
            .optional()
            .isMobilePhone()
            .withMessage('Please provide a valid phone number'),
    ],

    // Login validation
    login: [
        body('email')
            .isEmail()
            .withMessage('Please provide a valid email address')
            .normalizeEmail(),
        body('password')
            .isLength({ min: 1 })
            .withMessage('Please provide your password'),
    ],

    // Logout validation
    logout: [
        body('refreshToken')
            .isLength({ min: 1 })
            .withMessage('Refresh token is required'),
    ],

    // Refresh token validation
    refreshToken: [
        body('refreshToken')
            .isLength({ min: 1 })
            .withMessage('Refresh token is required'),
    ],

    // Verify phone validation
    verifyPhone: [
        body('code')
            .isLength({ min: 6, max: 6 })
            .withMessage('Verification code must be 6 digits')
            .isNumeric()
            .withMessage('Verification code must contain only numbers'),
    ],

    // Forgot password validation
    forgotPassword: [
        body('email')
            .isEmail()
            .withMessage('Please provide a valid email address')
            .normalizeEmail(),
    ],

    // Reset password validation
    resetPassword: [
        body('password')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters long')
            .matches(/\d/)
            .withMessage('Password must contain at least one number')
            .matches(/[a-zA-Z]/)
            .withMessage('Password must contain at least one letter'),
    ],

    // Change password validation
    changePassword: [
        body('currentPassword')
            .isLength({ min: 1 })
            .withMessage('Current password is required'),
        body('newPassword')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters long')
            .matches(/\d/)
            .withMessage('Password must contain at least one number')
            .matches(/[a-zA-Z]/)
            .withMessage('Password must contain at least one letter')
            .custom((value, { req }) => {
                if (value === req.body.currentPassword) {
                    throw new Error('New password must be different from current password');
                }
                return true;
            }),
    ],

    // Unlock account validation
    unlockAccount: [
        body('email')
            .isEmail()
            .withMessage('Please provide a valid email address')
            .normalizeEmail(),
    ],
};

// User validations
export const userValidation = {
    // Update user validation
    updateUser: [
        body('username')
            .optional()
            .isLength({ min: 3 })
            .withMessage('Username must be at least 3 characters long')
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username can only contain letters, numbers, and underscores'),
        body('firstName')
            .optional()
            .isLength({ min: 1 })
            .withMessage('First name cannot be empty'),
        body('lastName')
            .optional()
            .isLength({ min: 1 })
            .withMessage('Last name cannot be empty'),
        body('phoneNumber')
            .optional()
            .isMobilePhone()
            .withMessage('Please provide a valid phone number'),
        body('profilePicture')
            .optional()
            .isURL()
            .withMessage('Profile picture must be a valid URL'),
        body('role')
            .optional()
            .isIn(['user', 'admin'])
            .withMessage('Role must be either "user" or "admin"'),
        body('isEmailVerified')
            .optional()
            .isBoolean()
            .withMessage('Email verification status must be a boolean'),
        body('isPhoneVerified')
            .optional()
            .isBoolean()
            .withMessage('Phone verification status must be a boolean'),
        body('accountLocked')
            .optional()
            .isBoolean()
            .withMessage('Account locked status must be a boolean'),
    ],
};

export default {
    authValidation,
    userValidation,
};