import User from '../models/User.js';
import * as tokenService from '../services/token.service.js';
import * as emailService from '../services/email.service.js';
import AppError from '../utils/AppError.js';
import catchAsync from "../utils/catchAsync.js";
import passport from 'passport';

/**
 * Register a new user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const register = catchAsync(async (req, res, next) => {
    const { email, password, username, firstName, lastName, phoneNumber } = req.body;

    // Check if email is already taken
    const existingUser = await User.findOne({ email });

    if (existingUser) {
        return next(new AppError('Email is already taken', 400));
    }

    // Create a new user
    const user = await User.create({ email, password, username, firstName, lastName, phoneNumber });

    // Generate a verification token
    const verificationToken = await tokenService.generateVerifyEmailToken(user._id);

    // Send verification email
    await emailService.sendVerificationEmail(user.email, verificationToken);

    // Generate tokens
    const tokens = await tokenService.generateAuthTokens(
        user,
        req.headers['user-agent'],
        req.ip
    );

    // Update last login time
    user.lastLogin = Date.now();
    await user.save();

    // Response
    res.status(201).json({
        message: 'User registered successfully',
        user: {
            id: user._id,
            email: user.email,
            username: user.username,
            isEmailVerified: user.isEmailVerified,
            isPhoneVerified: user.isPhoneVerified
        },
        tokens: {
            access: tokens.access,
            refresh: tokens.refresh
        }
    });
});

/**
 * Get current user profile
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const getCurrentUser = catchAsync(async (req, res, next) => {
    try {
        const userId = req.user.id; // Set by auth middleware

        const user = await User.findById(userId).select('-password');
        if (!user) {
            return next(new AppError(404, 'User not found'));
        }

        res.status(200).json({
            status: 'success',
            data: { user }
        });
    } catch (error) {
        next(error);
    }
});

/**
 * Log out from all devices
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const logoutAll = catchAsync(async (req, res, next) => {
    try {
        const userId = req.user.id; // Set by auth middleware

        // Delete all refresh tokens for the user
        const result = await tokenService.deleteUserTokens(userId, 'refresh');

        res.status(200).json({
            status: 'success',
            message: `Logged out from all devices. ${result.deletedCount} sessions terminated.`
        });
    } catch (error) {
        next(error);
    }
});

/**
 * Unlock a user account that was locked due to too many failed login attempts
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const unlockAccount = catchAsync(async (req, res, next) => {
    try {
        const { email } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            // For security reasons, don't reveal if email exists
            return res.status(200).json({
                status: 'success',
                message: 'If the account exists and is locked, an unlock email has been sent'
            });
        }

        // Check if account is actually locked
        if (!user.accountLocked) {
            return res.status(200).json({
                status: 'success',
                message: 'If the account exists and is locked, an unlock email has been sent'
            });
        }

        // Generate account unlock token
        const unlockToken = tokenService.generateResetPasswordToken(user._id);

        // Send unlock email
        await emailService.sendAccountUnlockEmail(user.email, unlockToken);

        res.status(200).json({
            status: 'success',
            message: 'If the account exists and is locked, an unlock email has been sent'
        });
    } catch (error) {
        next(error);
    }
});

/**
 * Process account unlock request
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const processUnlockAccount = catchAsync(async (req, res, next) => {
    try {
        const { token } = req.params;

        // Find token in database
        const tokenDoc = await tokenService.findToken(token, 'resetPassword');
        if (!tokenDoc) {
            return next(new AppError('Invalid or expired token', 404));
        }

        // Find and update user
        const user = await User.findByIdAndUpdate(
            tokenDoc.user,
            {
                accountLocked: false,
                loginAttempts: 0
            },
            { new: true }
        );

        if (!user) {
            return next(new AppError('User not found', 404));
        }

        // Delete token
        await tokenService.deleteToken(tokenDoc._id);

        // Determine if we should redirect or send JSON response
        if (req.query.redirect === 'true') {
            res.redirect(`${process.env.CLIENT_URL}/account-unlocked`);
        } else {
            res.status(200).json({
                status: 'success',
                message: 'Account unlocked successfully'
            });
        }
    } catch (error) {
        next(error);
    }
});

/**
 * Login user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const login = (req, res, next) => {
    passport.authenticate('local', { session: false }, async (err, user, info) => {
        try {
            if (err) {
                return next(err);
            }

            if (!user) {
                return next(new AppError(info?.message || 'Invalid email or password', 401));
            }

            // Generate auth tokens
            const tokens = await tokenService.generateAuthTokens(
                user,
                req.headers['user-agent'],
                req.ip
            );

            // Update last login time
            user.lastLogin = new Date();
            await user.save();

            // Check if we should send login notification
            if (req.body.notifyLogin !== false) {
                try {
                    // Get location info from IP (simplified, would use a geolocation service in production)
                    const location = req.ip || 'unknown location';
                    const device = req.headers['user-agent'] || 'unknown device';

                    // Send login notification email
                    await emailService.sendLoginNotificationEmail(user.email, {
                        device,
                        location,
                        ip: req.ip,
                        time: new Date()
                    });

                    // Send SMS notification if phone is verified
                    if (user.isPhoneVerified && user.phoneNumber) {
                        // await smsService.sendLoginNotificationSms(
                        //     user.phoneNumber,
                        //     location,
                        //     new Date()
                        // );
                    }
                } catch (notifyError) {
                    // Log but don't fail if notification sending fails
                    console.error('Error sending login notification:', notifyError);
                }
            }

            // Response
            res.status(200).json({
                status: 'success',
                message: 'Login successful',
                data: {
                    user: {
                        id: user._id,
                        email: user.email,
                        username: user.username,
                        isEmailVerified: user.isEmailVerified,
                        isPhoneVerified: user.isPhoneVerified,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        role: user.role
                    },
                    tokens: {
                        access: tokens.access,
                        refresh: tokens.refresh
                    }
                }
            });
        } catch (error) {
            next(error);
        }
    })(req, res, next);
};

/**
 * Logout user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const logout = async (req, res, next) => {
    try {
        // Get refresh token from request
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return next(new AppError(400, 'Refresh token is required'));
        }

        // Find token in database
        const token = await tokenService.findToken(refreshToken, 'refresh');
        if (!token) {
            return next(new AppError(404, 'Token not found'));
        }

        // Blacklist token
        await tokenService.blacklistToken(token._id);

        res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
        next(error);
    }
};

/**
 * Refresh access token
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const refreshToken = async (req, res, next) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return next(new AppError(400, 'Refresh token is required'));
        }

        // Verify token
        let payload;
        try {
            payload = tokenService.verifyToken(refreshToken);
        } catch (error) {
            return next(new AppError(401, 'Invalid or expired refresh token'));
        }

        // Find token in database
        const token = await tokenService.findToken(refreshToken, 'refresh');
        if (!token) {
            return next(new AppError(404, 'Token not found'));
        }

        // Find user
        const user = await User.findById(payload.sub);
        if (!user) {
            return next(new AppError(404, 'User not found'));
        }

        // Generate new tokens
        const tokens = await tokenService.generateAuthTokens(
            user,
            req.headers['user-agent'],
            req.ip
        );

        // Blacklist old token
        await tokenService.blacklistToken(token._id);

        // Response
        res.status(200).json({
            tokens: {
                access: tokens.access,
                refresh: tokens.refresh
            }
        });
    } catch (error) {
        next(error);
    }
};

/**
 * Send verification email
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const sendVerificationEmail = async (req, res, next) => {
    try {
        const { userId } = req.params;

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return next(new AppError(404, 'User not found'));
        }

        // Check if email is already verified
        if (user.isEmailVerified) {
            return next(new AppError(400, 'Email already verified'));
        }

        // Generate verification token
        const verificationToken = tokenService.generateVerifyEmailToken(user._id);

        // Send verification email
        await emailService.sendVerificationEmail(user.email, verificationToken);

        res.status(200).json({ message: 'Verification email sent' });
    } catch (error) {
        next(error);
    }
};

/**
 * Verify email
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const verifyEmail = async (req, res, next) => {
    try {
        const { token } = req.params;

        // Find token in database
        const tokenDoc = await tokenService.findToken(token, 'verifyEmail');
        if (!tokenDoc) {
            return next(new AppError(404, 'Token not found or expired'));
        }

        // Find and update user
        const user = await User.findByIdAndUpdate(
            tokenDoc.user,
            { isEmailVerified: true },
            { new: true }
        );

        if (!user) {
            return next(new AppError(404, 'User not found'));
        }

        // Delete token
        await tokenService.deleteToken(tokenDoc._id);

        res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
        next(error);
    }
};

/**
 * Forgot password
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const forgotPassword = async (req, res, next) => {
    try {
        const { email } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            // For security reasons, don't reveal if email exists
            return res.status(200).json({ message: 'Password reset email sent if email exists' });
        }

        // Generate reset token
        const resetToken = await tokenService.generateResetPasswordToken(user._id);

        // Send reset email
        await emailService.sendResetPasswordEmail(user.email, resetToken);

        res.status(200).json({ message: 'Password reset email sent' });
    } catch (error) {
        next(error);
    }
};

/**
 * Reset password
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const resetPassword = async (req, res, next) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        // Find token in database
        const tokenDoc = await tokenService.findToken(token, 'resetPassword');
        if (!tokenDoc) {
            return next(new AppError(404, 'Token not found or expired'));
        }

        // Find user
        const user = await User.findById(tokenDoc.user);
        if (!user) {
            return next(new AppError(404, 'User not found'));
        }

        // Update password
        user.password = password;
        await user.save();

        // Delete token
        await tokenService.deleteToken(tokenDoc._id);

        // Delete all refresh tokens for the user
        await tokenService.deleteUserTokens(user._id, 'refresh');

        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        next(error);
    }
};

/**
 * Change password
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const changePassword = async (req, res, next) => {
    try {
        const { userId } = req.params;
        const { currentPassword, newPassword } = req.body;

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return next(new AppError(404, 'User not found'));
        }

        // Check if user has password (might not if they use OAuth)
        if (!user.password) {
            return next(new AppError(400, 'Cannot change password for OAuth accounts'));
        }

        // Verify current password
        const isPasswordValid = await user.comparePassword(currentPassword);
        if (!isPasswordValid) {
            return next(new AppError(401, 'Current password is incorrect'));
        }

        // Update password
        user.password = newPassword;
        await user.save();

        // Delete all refresh tokens for the user for security
        await tokenService.deleteUserTokens(user._id, 'refresh');

        res.status(200).json({ message: 'Password changed successfully' });
    }
    catch (error) {
        next(error);
    }
};

export default {
    register,
    login,
    logout,
    logoutAll,
    refreshToken,
    getCurrentUser,
    sendVerificationEmail,
    verifyEmail,
    forgotPassword,
    resetPassword,
    changePassword,
    unlockAccount,
    processUnlockAccount
};