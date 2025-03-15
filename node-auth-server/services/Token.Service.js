import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import moment from 'moment';
import Token from '../models/Token.Model.js';

/**
 * Generate JWT token
 * @param {Object} payload - Data to be included in token
 * @param {string} secret - Secret key for signing
 * @param {string|number} expiresIn - Token expiration time
 * @returns {string} JWT token
 */
export const generateToken = (payload, secret = process.env.JWT_SECRET, expiresIn = process.env.JWT_ACCESS_EXPIRATION) => {
    return jwt.sign(payload, secret, { expiresIn });
};

/**
 * Verify JWT token
 * @param {string} token - JWT token to verify
 * @param {string} secret - Secret key for verification
 * @returns {Object} Decoded token payload
 */
export const verifyToken = (token, secret = process.env.JWT_SECRET) => {
    return jwt.verify(token, secret);
};

/**
 * Parse duration string to milliseconds
 * @param {string} durationStr - Duration string (e.g., '15m', '1d', '7d')
 * @returns {number} Milliseconds
 */
export const parseDuration = (durationStr) => {
    const match = durationStr.match(/^(\d+)([smhdwy])$/);
    if (!match) return 0;

    const value = parseInt(match[1]);
    const unit = match[2];

    const msMap = {
        s: 1000,                // second
        m: 60 * 1000,           // minute
        h: 60 * 60 * 1000,      // hour
        d: 24 * 60 * 60 * 1000, // day
        w: 7 * 24 * 60 * 60 * 1000, // week
        y: 365 * 24 * 60 * 60 * 1000 // year (approximation)
    };

    return value * msMap[unit];
};

/**
 * Calculate expiry date from a duration string
 * @param {string} durationStr - Duration string (e.g., '15m', '1d', '7d')
 * @returns {Date} Expiry date
 */
export const calculateExpiryDate = (durationStr) => {
    const ms = parseDuration(durationStr);
    return new Date(Date.now() + ms);
};

/**
 * Generate auth tokens (access & refresh)
 * @param {Object} user - User object
 * @param {string} userAgent - User agent from request
 * @param {string} ipAddress - IP address from request
 * @returns {Object} Access and refresh tokens
 */
export const generateAuthTokens = async (user, userAgent, ipAddress) => {
    // Generate access token payload
    const accessTokenPayload = {
        sub: user._id,
        role: user.role,
        type: 'access',
    };

    // Generate refresh token payload
    const refreshTokenPayload = {
        sub: user._id,
        type: 'refresh',
    };

    // Get expiration times from env variables
    const accessExpiration = process.env.JWT_ACCESS_EXPIRATION || '15m';
    const refreshExpiration = process.env.JWT_REFRESH_EXPIRATION || '7d';

    // Calculate expiry times
    const accessTokenExpires = calculateExpiryDate(accessExpiration);
    const refreshTokenExpires = calculateExpiryDate(refreshExpiration);

    // Generate tokens
    const accessToken = generateToken(
        accessTokenPayload,
        process.env.JWT_SECRET,
        accessExpiration
    );

    const refreshToken = generateToken(
        refreshTokenPayload,
        process.env.JWT_SECRET,
        refreshExpiration
    );

    // Save refresh token in database
    await saveToken(
        refreshToken,
        user._id,
        'refresh',
        refreshTokenExpires,
        userAgent,
        ipAddress
    );

    return {
        access: {
            token: accessToken,
            expires: accessTokenExpires,
        },
        refresh: {
            token: refreshToken,
            expires: refreshTokenExpires,
        },
    };
};

/**
 * Generate reset password token
 * @param {string} userId - User ID
 * @returns {string} Reset password token
 */
export const generateResetPasswordToken = async (userId) => {
    const token = crypto.randomBytes(32).toString('hex');
    const expiration = process.env.JWT_RESET_PASSWORD_EXPIRATION || '10m';
    const expires = calculateExpiryDate(expiration);

    await saveToken(token, userId, 'resetPassword', expires);
    return token;
};


/**
 * Generate email verification token
 * @param {string} userId - User ID
 * @returns {string} Email verification token
 */
export const generateVerifyEmailToken = async (userId) => {
    const token = crypto.randomBytes(32).toString('hex');
    const expiration = process.env.JWT_VERIFY_EMAIL_EXPIRATION || '1d';
    const expires = calculateExpiryDate(expiration);

    console.log('moment:', moment());
    console.log('process.env.JWT_VERIFY_EMAIL_EXPIRATION:', process.env.JWT_VERIFY_EMAIL_EXPIRATION);
    console.log('Token:', expires);

    await saveToken(token, userId, 'verifyEmail', expires);
    return token;
};

/**
 * Generate SMS verification token
 * @param {string} userId - User ID
 * @returns {string} SMS verification token (6-digit code)
 */
export const generateVerifySmsToken = async (userId) => {
    // Generate a 6-digit code
    const token = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = calculateExpiryDate('10m');  // 10 minutes expiry

    await saveToken(token, userId, 'verifySms', expires);
    return token;
};

/**
 * Save a token in the database
 * @param {string} token - Token value
 * @param {string} userId - User ID
 * @param {string} type - Token type
 * @param {Date} expires - Expiration date
 * @param {string} [userAgent] - User agent
 * @param {string} [ipAddress] - IP address
 * @returns {Promise<Token>} Saved token document
 */
export const saveToken = async (
    token,
    userId,
    type,
    expires,
    userAgent = null,
    ipAddress = null
) => {
    const tokenDoc = await Token.create({
        token,
        user: userId,
        type,
        expires,
        userAgent,
        ipAddress,
    });

    return tokenDoc;
};

/**
 * Find token by value and type
 * @param {string} token - Token value
 * @param {string} type - Token type
 * @returns {Promise<Token>} Token document
 */
export const findToken = async (token, type) => {
    return Token.findOne({
        token,
        type,
        blacklisted: false,
        expires: { $gt: new Date() },
    });
};

/**
 * Delete a token by ID
 * @param {string} id - Token ID
 * @returns {Promise<Token>} Deleted token document
 */
export const deleteToken = async (id) => {
    return Token.findByIdAndDelete(id);
};

/**
 * Blacklist a token
 * @param {string} id - Token ID
 * @returns {Promise<Token>} Updated token document
 */
export const blacklistToken = async (id) => {
    return Token.findByIdAndUpdate(id, { blacklisted: true }, { new: true });
};

/**
 * Delete all tokens for a user by type
 * @param {string} userId - User ID
 * @param {string} [type] - Token type (optional)
 * @returns {Promise<Object>} Result of deletion operation
 */
export const deleteUserTokens = async (userId, type = null) => {
    const query = { user: userId };
    if (type) {
        query.type = type;
    }

    return Token.deleteMany(query);
};

export default {
    generateToken,
    verifyToken,
    generateAuthTokens,
    generateResetPasswordToken,
    generateVerifyEmailToken,
    generateVerifySmsToken,
    saveToken,
    findToken,
    deleteToken,
    blacklistToken,
    deleteUserTokens,
};