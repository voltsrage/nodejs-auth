import passport from "passport";
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { Strategy as AppleStrategy } from 'passport-apple';
import { Strategy as LineStrategy } from 'passport-line';
import User from '../models/user';
import AppError from '../utils/appError';

// Configure Local Strategy for username/password authentication
passport.use(
    new LocalStrategy(
        {
            usernameField: 'email',
            passwordField: 'password'
        },
        async (email, password, done) => {
            try {
                const user = await User.findOne({ email });

                // If user not found or password incorrect
                if (!user || !(await user.comparePassword(password))) {
                    return done(null, false, { message: 'Incorrect email or password' });
                }

                // If account is locked
                if (user.accountLocked) {
                    return done(null, false, { message: 'Account is locked due to too many failed attempts' });
                }

                // Update login attempts (reset to 0)
                await user.checkLoginAttempts(true);

                // Authentication successful
                return done(null, user);
            } catch (error) {
                return done(error);
            }
        }
    )
)

// Configure Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(
        new GoogleStrategy(
            {
                clientID: process.env.GOOGLE_CLIENT_ID,
                clientSecret: process.env.GOOGLE_CLIENT_SECRET,
                callbackURL: process.env.GOOGLE_CALLBACK_URL,
                passReqToCallback: true,
            },
            async (req, accessToken, refreshToken, profile, done) => {
                try {
                    return done(null, profile);
                } catch (error) {
                    return done(error);
                }
            }
        )
    );
} else {
    console.warn('Google OAuth credentials not found. Google authentication will not work.');
}

// Configure Facebook OAuth Strategy
if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
    passport.use(
        new FacebookStrategy(
            {
                clientID: process.env.FACEBOOK_APP_ID,
                clientSecret: process.env.FACEBOOK_APP_SECRET,
                callbackURL: process.env.FACEBOOK_CALLBACK_URL,
                profileFields: ['id', 'emails', 'name', 'picture.type(large)'],
                passReqToCallback: true,
            },
            async (req, accessToken, refreshToken, profile, done) => {
                try {
                    return done(null, profile);
                } catch (error) {
                    return done(error);
                }
            }
        )
    );
} else {
    console.warn('Facebook OAuth credentials not found. Facebook authentication will not work.');
}

// Configure Apple OAuth Strategy
if (process.env.APPLE_CLIENT_ID && process.env.APPLE_TEAM_ID && process.env.APPLE_KEY_ID) {
    passport.use(
        new AppleStrategy(
            {
                clientID: process.env.APPLE_CLIENT_ID,
                teamID: process.env.APPLE_TEAM_ID,
                keyID: process.env.APPLE_KEY_ID,
                keyFilePath: process.env.APPLE_PRIVATE_KEY_PATH,
                callbackURL: process.env.APPLE_CALLBACK_URL,
                passReqToCallback: true,
            },
            async (req, accessToken, refreshToken, idToken, profile, done) => {
                try {
                    // Apple doesn't provide much profile information by default
                    // The email and name may only be provided on the first login
                    // We need to store this information when we first receive it

                    return done(null, profile);
                } catch (error) {
                    return done(error);
                }
            }
        )
    );
} else {
    console.warn('Apple OAuth credentials not found. Apple authentication will not work.');
}

// Configure LINE OAuth Strategy
if (process.env.LINE_CLIENT_ID && process.env.LINE_CLIENT_SECRET) {
    passport.use(
        new LineStrategy(
            {
                channelID: process.env.LINE_CLIENT_ID,
                channelSecret: process.env.LINE_CLIENT_SECRET,
                callbackURL: process.env.LINE_CALLBACK_URL,
                scope: ['profile', 'openid', 'email'],
                botPrompt: 'normal',
                passReqToCallback: true,
            },
            async (req, accessToken, refreshToken, profile, done) => {
                try {
                    return done(null, profile);
                } catch (error) {
                    return done(error);
                }
            }
        )
    );
} else {
    console.warn('LINE OAuth credentials not found. LINE authentication will not work.');
}

export default passport;