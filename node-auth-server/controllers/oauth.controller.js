import passport from 'passport';
import User from '../models/User.js';
import * as tokenService from '../services/token.service.js';
import * as emailService from '../services/email.service.js';
import AppError from '../utils/AppError.js';

/**
 * Initialize OAuth flow for a provider
 * @param {string} provider - OAuth provider name
 * @returns {Function} Express middleware
 */
export const initiateOAuth = (provider) => {
    return (req, res, next) => {
        const state = req.query.state || '';
        const scopes = getProviderScopes(provider);

        return passport.authenticate(provider, {
            session: false,
            scope: scopes,
            state: state,
            // Add provider-specific options
            ...(provider === 'google' && {
                prompt: 'select_account',
                accessType: 'offline',
                includeGrantedScopes: true
            }),
            ...(provider === 'facebook' && {
                authType: 'rerequest',
                display: 'popup',
                enableProof: true
            }),
            ...(provider === 'apple' && {
                authType: 'rerequest',
                passReqToCallback: true,
            }),
            ...(provider === 'line' && {
                botPrompt: 'normal',
                uiLocales: req.query.locale || 'en',
            }),
        })(req, res, next);
    };
};

/**
 * Handle OAuth callback with Passport
 * @param {string} provider - OAuth provider name
 * @returns {Function} Express middleware
 */
export const handleOAuthCallback = (provider) => {
    return (req, res, next) => {
        const options = {
            session: false,
            failureRedirect: `${process.env.CLIENT_URL}/auth/error?provider=${provider}`,
        };

        passport.authenticate(provider, options, async (err, profile, info) => {
            try {
                if (err) {
                    console.error(`OAuth ${provider} error:`, err);
                    return next(new AppError(`Authentication with ${provider} failed`, 401));
                }

                if (!profile) {
                    return next(new AppError(`Failed to retrieve profile from ${provider}`, 401));
                }

                // Process the user profile
                const userData = await processOAuthProfile(provider, profile);

                // Generate tokens
                const tokens = await tokenService.generateAuthTokens(
                    userData.user,
                    req.headers['user-agent'],
                    req.ip
                );

                // Update last login
                userData.user.lastLogin = new Date();
                await userData.user.save();

                // Handle response based on the client's needs
                // For web applications, redirecting with query params is common
                // For mobile apps, you may want to redirect to a custom URL scheme

                // Build redirect URL with tokens
                const redirectUrl = buildRedirectUrl(req, userData, tokens);

                res.redirect(redirectUrl);
            } catch (error) {
                next(error);
            }
        })(req, res, next);
    };
};

/**
 * Handle OAuth linking flow (connecting provider to existing account)
 * @param {string} provider - OAuth provider name
 * @returns {Function} Express middleware
 */
export const handleOAuthLinking = (provider) => {
    return (req, res, next) => {
        // Ensure user is authenticated
        if (!req.user) {
            return next(new AppError('You must be logged in to link accounts', 401));
        }

        const options = {
            session: false,
            failureRedirect: `${process.env.CLIENT_URL}/profile/linked-accounts?error=Failed+to+link+${provider}+account`,
        };

        passport.authenticate(provider, options, async (err, profile, info) => {
            try {
                if (err) {
                    console.error(`OAuth ${provider} linking error:`, err);
                    return next(new AppError(`Linking with ${provider} failed`, 401));
                }

                if (!profile) {
                    return next(new AppError(`Failed to retrieve profile from ${provider}`, 401));
                }

                // Get provider ID and email
                const { id: oauthId, emails } = profile;

                // Get email from provider profile
                const email = getEmailFromProfile(profile);

                if (!email) {
                    return next(new AppError(`Could not retrieve email from ${provider}`, 400));
                }

                // Check if the provider account is already linked to another user
                const existingUser = await User.findOne({
                    oauthProvider: provider,
                    oauthId,
                });

                if (existingUser && existingUser._id.toString() !== req.user.id) {
                    return next(new AppError(`This ${provider} account is already linked to another user`, 409));
                }

                // Check if the email matches the authenticated user's email
                const currentUser = await User.findById(req.user.id);

                if (currentUser.email !== email) {
                    return next(new AppError(
                        `The ${provider} account email (${email}) does not match your account email (${currentUser.email})`,
                        400
                    ));
                }

                // Update user with OAuth provider info
                currentUser.oauthProvider = provider;
                currentUser.oauthId = oauthId;

                // If the user's email wasn't verified before, verify it now
                // since the OAuth provider has verified it
                if (!currentUser.isEmailVerified) {
                    currentUser.isEmailVerified = true;
                }

                await currentUser.save();

                // Redirect to profile page with success message
                res.redirect(`${process.env.CLIENT_URL}/profile/linked-accounts?success=true&provider=${provider}`);
            } catch (error) {
                next(error);
            }
        })(req, res, next);
    };
};

/**
 * Unlink OAuth provider from user account
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const unlinkOAuth = async (req, res, next) => {
    try {
        const { provider } = req.params;
        const userId = req.user.id;

        // Validate provider
        if (!['google', 'facebook', 'apple', 'line'].includes(provider)) {
            return next(new AppError('Invalid provider', 400));
        }

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return next(new AppError('User not found', 404));
        }

        // Check if user has password (required for unlinking)
        if (!user.password) {
            return next(new AppError(
                'You need to set a password before unlinking your social account',
                400
            ));
        }

        // Check if the provider is currently linked
        if (user.oauthProvider !== provider) {
            return next(new AppError(`Your account is not linked with ${provider}`, 400));
        }

        // Unlink the provider
        user.oauthProvider = null;
        user.oauthId = null;
        await user.save();

        res.status(200).json({
            status: 'success',
            message: `Your account has been unlinked from ${provider}`,
        });
    } catch (error) {
        next(error);
    }
};

/**
 * Process OAuth user profile
 * @param {string} provider - OAuth provider name
 * @param {Object} profile - User profile from OAuth provider
 * @returns {Promise<Object>} User data
 */
const processOAuthProfile = async (provider, profile) => {
    // Extract relevant data from the profile
    const { id: oauthId } = profile;
    const email = getEmailFromProfile(profile);
    const firstName = getFirstNameFromProfile(provider, profile);
    const lastName = getLastNameFromProfile(provider, profile);
    const profilePicture = getProfilePictureFromProfile(provider, profile);

    if (!email) {
        throw new AppError(`Could not retrieve email from ${provider}`, 400);
    }

    // Check if user exists with this OAuth ID
    let user = await User.findOne({
        oauthProvider: provider,
        oauthId,
    });

    // If user exists, return it
    if (user) {
        return { user, isNewUser: false };
    }

    // Check if user exists with this email
    user = await User.findOne({ email });

    if (user) {
        // If user exists with email but no OAuth, link the account
        if (!user.oauthProvider) {
            user.oauthProvider = provider;
            user.oauthId = oauthId;

            // If user has a profile picture from OAuth but not in our db, add it
            if (!user.profilePicture && profilePicture) {
                user.profilePicture = profilePicture;
            }

            // If user wasn't email verified before, verify now
            if (!user.isEmailVerified) {
                user.isEmailVerified = true;
            }

            await user.save();
            return { user, isNewUser: false };
        } else if (user.oauthProvider !== provider) {
            // User already exists with a different OAuth provider
            throw new AppError(
                `Email ${email} is already associated with another account using ${user.oauthProvider}`,
                409
            );
        }
    }

    // Create a new user
    const username = generateUsername(email, firstName, lastName);

    user = await User.create({
        email,
        username,
        firstName,
        lastName,
        oauthProvider: provider,
        oauthId,
        profilePicture,
        isEmailVerified: true, // Auto-verify email for OAuth users
    });

    // Send welcome email
    try {
        await emailService.sendEmail({
            to: email,
            subject: 'Welcome to our platform',
            template: 'welcome',
            data: {
                title: 'Welcome to Our Platform',
                message: `Thank you for signing up with ${provider}. Your account has been created successfully.`,
                firstName: firstName || username,
                supportEmail: process.env.SUPPORT_EMAIL || 'support@auth-server.com',
                year: new Date().getFullYear(),
            },
        });
    } catch (emailError) {
        console.error('Failed to send welcome email:', emailError);
        // Don't throw the error, continue with user creation
    }

    return { user, isNewUser: true };
};

/**
 * Get email from OAuth profile
 * @param {Object} profile - User profile from OAuth provider 
 * @returns {string|null} Email address
 */
const getEmailFromProfile = (profile) => {
    // Handle different profile structures
    if (profile.emails && profile.emails.length > 0) {
        return profile.emails[0].value;
    }

    if (profile.email) {
        return profile.email;
    }

    if (profile._json && profile._json.email) {
        return profile._json.email;
    }

    return null;
};

/**
 * Get first name from OAuth profile
 * @param {string} provider - OAuth provider name
 * @param {Object} profile - User profile from OAuth provider
 * @returns {string|null} First name
 */
const getFirstNameFromProfile = (provider, profile) => {
    if (provider === 'google' || provider === 'facebook') {
        if (profile.name && profile.name.givenName) {
            return profile.name.givenName;
        }
    }

    if (provider === 'apple') {
        if (profile.name && profile.name.firstName) {
            return profile.name.firstName;
        }
    }

    if (provider === 'line') {
        if (profile.displayName) {
            return profile.displayName.split(' ')[0];
        }
    }

    if (profile.displayName) {
        return profile.displayName.split(' ')[0];
    }

    return null;
};

/**
 * Get last name from OAuth profile
 * @param {string} provider - OAuth provider name
 * @param {Object} profile - User profile from OAuth provider
 * @returns {string|null} Last name
 */
const getLastNameFromProfile = (provider, profile) => {
    if (provider === 'google' || provider === 'facebook') {
        if (profile.name && profile.name.familyName) {
            return profile.name.familyName;
        }
    }

    if (provider === 'apple') {
        if (profile.name && profile.name.lastName) {
            return profile.name.lastName;
        }
    }

    if (provider === 'line') {
        if (profile.displayName) {
            const parts = profile.displayName.split(' ');
            return parts.length > 1 ? parts.slice(1).join(' ') : null;
        }
    }

    if (profile.displayName) {
        const parts = profile.displayName.split(' ');
        return parts.length > 1 ? parts.slice(1).join(' ') : null;
    }

    return null;
};

/**
 * Get profile picture from OAuth profile
 * @param {string} provider - OAuth provider name
 * @param {Object} profile - User profile from OAuth provider
 * @returns {string|null} Profile picture URL
 */
const getProfilePictureFromProfile = (provider, profile) => {
    if (provider === 'google') {
        if (profile.photos && profile.photos.length > 0) {
            return profile.photos[0].value;
        }
    }

    if (provider === 'facebook') {
        if (profile.photos && profile.photos.length > 0) {
            return profile.photos[0].value;
        }
        if (profile._json && profile._json.picture && profile._json.picture.data && profile._json.picture.data.url) {
            return profile._json.picture.data.url;
        }
    }

    if (provider === 'line') {
        if (profile.pictureUrl) {
            return profile.pictureUrl;
        }
    }

    return null;
};

/**
 * Generate username based on email and name
 * @param {string} email - User email
 * @param {string} firstName - User first name
 * @param {string} lastName - User last name
 * @returns {string} Username
 */
const generateUsername = (email, firstName, lastName) => {
    // First try: Use the first part of the email
    let username = email.split('@')[0];

    // Second try: If first name and last name are available
    if (firstName && lastName) {
        // Combine first name and first letter of last name
        username = (firstName + lastName.charAt(0)).toLowerCase();
    } else if (firstName) {
        username = firstName.toLowerCase();
    }

    // Remove special characters and spaces
    username = username.replace(/[^a-zA-Z0-9]/g, '');

    // Add random suffix to prevent duplicates
    const randomSuffix = Math.floor(Math.random() * 1000);
    username = `${username}${randomSuffix}`;

    return username;
};

/**
 * Get appropriate scopes for each provider
 * @param {string} provider - OAuth provider name
 * @returns {string[]} Array of scopes
 */
const getProviderScopes = (provider) => {
    switch (provider) {
        case 'google':
            return ['profile', 'email'];
        case 'facebook':
            return ['email', 'public_profile'];
        case 'apple':
            return ['name', 'email'];
        case 'line':
            return ['profile', 'openid', 'email'];
        default:
            return ['email'];
    }
};


/**
 * Build redirect URL with tokens
 * @param {Object} req - Express request object
 * @param {Object} userData - User data
 * @param {Object} tokens - Auth tokens
 * @returns {string} Redirect URL
 */
const buildRedirectUrl = (req, userData, tokens) => {
    const baseUrl = process.env.CLIENT_URL || 'http://localhost:3000';
    const queryParams = new URLSearchParams({
        accessToken: tokens.access.token,
        refreshToken: tokens.refresh.token,
        expiresIn: new Date(tokens.access.expires).getTime(),
        isNewUser: userData.isNewUser.toString(),
    });

    // Handling deep linking for mobile apps
    if (req.query.platform === 'mobile') {
        // For mobile apps, you might use a custom URL scheme
        const scheme = process.env.MOBILE_APP_SCHEME || 'myapp';
        return `${scheme}://auth/callback?${queryParams.toString()}`;
    }

    // For web applications
    return `${baseUrl}/auth/callback?${queryParams.toString()}`;
};

export default {
    initiateOAuth,
    handleOAuthCallback,
    handleOAuthLinking,
    unlinkOAuth
};