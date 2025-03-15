import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import moment from 'moment';
import Token from '../models/Token.Model';

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

    // Calculate expiry times
    const accessTokenExpires = moment().add(
        process.env.JWT_ACCESS_EXPIRATION || '15m'
    );

    const refreshTokenExpires = moment().add(
        process.env.JWT_REFRESH_EXPIRATION || '7d'
    );

    // Generate tokens
    const accessToken = generateToken(
        accessTokenPayload,
        process.env.JWT_SECRET,
        process.env.JWT_ACCESS_EXPIRATION
    );

    const refreshToken = generateToken(
        refreshTokenPayload,
        process.env.JWT_SECRET,
        process.env.JWT_REFRESH_EXPIRATION
    );

    // Save refresh token in database
    await saveToken(
        refreshToken,
        user._id,
        'refresh',
        refreshTokenExpires.toDate(),
        userAgent,
        ipAddress
    );

    return {
        access: {
            token: accessToken,
            expires: accessTokenExpires.toDate(),
        },
        refresh: {
            token: refreshToken,
            expires: refreshTokenExpires.toDate(),
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
    const expires = moment().add(
        process.env.JWT_RESET_PASSWORD_EXPIRATION || '10m'
    ).toDate();

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
    const expires = moment().add(
        process.env.JWT_VERIFY_EMAIL_EXPIRATION || '1d'
    ).toDate();

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
    const expires = moment().add('10m').toDate(); // 10 minutes expiry

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