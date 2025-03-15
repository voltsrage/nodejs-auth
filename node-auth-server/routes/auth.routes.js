import express from 'express';
import authController from '../controllers/auth.controller.js';
import { validate } from '../middleware/validator.js';
import { authValidation } from '../utils/validation.js';
import authenticate from '../middleware/auth.js';

const router = express.Router();

/**
 * @route POST /api/auth/register
 * @desc Register a new user
 * @access Public
 */
router.post(
    '/register',
    validate(authValidation.register),
    authController.register
);

/**
 * @route POST /api/auth/login
 * @desc Login a user
 * @access Public
 */
router.post(
    '/login',
    validate(authValidation.login),
    authController.login
);

/**
 * @route POST /api/auth/logout
 * @desc Logout a user
 * @access Public
 */
router.post(
    '/logout',
    validate(authValidation.logout),
    authController.logout
);

/**
 * @route POST /api/auth/logout-all
 * @desc Logout from all devices
 * @access Private
 */
router.post(
    '/logout-all',
    authenticate(),
    authController.logoutAll
);

/**
 * @route POST /api/auth/refresh-token
 * @desc Refresh access token
 * @access Public
 */
router.post(
    '/refresh-token',
    validate(authValidation.refreshToken),
    authController.refreshToken
);

/**
 * @route GET /api/auth/me
 * @desc Get current user profile
 * @access Private
 */
router.get(
    '/me',
    authenticate(),
    authController.getCurrentUser
);

/**
 * @route POST /api/auth/verify-email
 * @desc Send verification email to current user
 * @access Private
 */
router.post(
    '/verify-email',
    authenticate(),
    authController.sendVerificationEmail
);

/**
 * @route POST /api/auth/verify-email/:userId
 * @desc Send verification email to specific user (admin only)
 * @access Private/Admin
 */
router.post(
    '/verify-email/:userId',
    authenticate(['admin']),
    authController.sendVerificationEmail
);

/**
 * @route GET /api/auth/verify-email/:token
 * @desc Verify email with token
 * @access Public
 */
router.get(
    '/verify-email/:token',
    authController.verifyEmail
);

/**
 * @route POST /api/auth/verify-phone
 * @desc Send verification SMS to current user
 * @access Private
 */
// router.post(
//     '/verify-phone',
//     authenticate(),
//     authController.sendVerificationSms
// );

/**
 * @route POST /api/auth/verify-phone/:userId
 * @desc Send verification SMS to specific user (admin only)
 * @access Private/Admin
 */
// router.post(
//     '/verify-phone/:userId',
//     authenticate(['admin']),
//     authController.sendVerificationSms
// );

/**
 * @route POST /api/auth/verify-phone/confirm
 * @desc Verify phone with code for current user
 * @access Private
 */
// router.post(
//     '/verify-phone/confirm',
//     authenticate(),
//     validate(authValidation.verifyPhone),
//     authController.verifyPhone
// );

/**
 * @route POST /api/auth/verify-phone/:userId/confirm
 * @desc Verify phone with code for specific user (admin only)
 * @access Private/Admin
 */
// router.post(
//     '/verify-phone/:userId/confirm',
//     authenticate(['admin']),
//     validate(authValidation.verifyPhone),
//     authController.verifyPhone
// );

/**
 * @route POST /api/auth/forgot-password
 * @desc Request password reset
 * @access Public
 */
router.post(
    '/forgot-password',
    validate(authValidation.forgotPassword),
    authController.forgotPassword
);

/**
 * @route POST /api/auth/reset-password/:token
 * @desc Reset password with token
 * @access Public
 */
router.post(
    '/reset-password/:token',
    validate(authValidation.resetPassword),
    authController.resetPassword
);

/**
 * @route PUT /api/auth/change-password
 * @desc Change password for current user
 * @access Private
 */
router.put(
    '/change-password',
    authenticate(),
    validate(authValidation.changePassword),
    authController.changePassword
);

/**
 * @route PUT /api/auth/change-password/:userId
 * @desc Change password for specific user (admin only)
 * @access Private/Admin
 */
router.put(
    '/change-password/:userId',
    authenticate(['admin']),
    validate(authValidation.changePassword),
    authController.changePassword
);

/**
 * @route POST /api/auth/unlock-account
 * @desc Request account unlock (for locked accounts)
 * @access Public
 */
router.post(
    '/unlock-account',
    validate(authValidation.unlockAccount),
    authController.unlockAccount
);

/**
 * @route GET /api/auth/unlock-account/:token
 * @desc Process account unlock with token
 * @access Public
 */
router.get(
    '/unlock-account/:token',
    authController.processUnlockAccount
);

export default router;