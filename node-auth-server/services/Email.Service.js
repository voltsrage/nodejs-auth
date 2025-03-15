import nodemailer from 'nodemailer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import handlebars from 'handlebars';
import AppError from '../utils/AppError.js';

// Get directory path in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Create a nodemailer transport
 * @returns {nodemailer.Transporter} Nodemailer transport
 */
const createTransport = () => {
    // For production
    if (process.env.NODE_ENV === 'production') {
        return nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: process.env.SMTP_PORT,
            secure: process.env.SMTP_PORT === '465',
            auth: {
                user: process.env.SMTP_USERNAME,
                pass: process.env.SMTP_PASSWORD,
            },
        });
    }

    // For development - use Ethereal (fake SMTP service)
    return nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
            user: process.env.ETHEREAL_USERNAME || 'ethereal.user@ethereal.email',
            pass: process.env.ETHEREAL_PASSWORD || 'ethereal_password',
        },
    });
};

/**
 * Read and compile an email template
 * @param {string} templateName - Name of the template file
 * @returns {Promise<Function>} Compiled handlebars template
 */
const getEmailTemplate = async (templateName) => {
    try {
        const templatePath = path.join(__dirname, '../public/templates', `${templateName}.html`);
        const templateSource = await fs.readFile(templatePath, 'utf-8');
        return handlebars.compile(templateSource);
    } catch (error) {
        console.error(`Error loading email template "${templateName}":`, error);
        throw new AppError('Failed to load email template', 500);
    }
};

/**
 * Send an email
 * @param {Object} options - Email options
 * @param {string} options.to - Recipient email address
 * @param {string} options.subject - Email subject
 * @param {string} options.template - Template name
 * @param {Object} options.data - Template data
 * @returns {Promise<Object>} Email send info
 */
export const sendEmail = async (options) => {
    try {
        const { to, subject, template, data } = options;

        // Get and compile template
        const compiledTemplate = await getEmailTemplate(template);
        const html = compiledTemplate(data);

        // Get transport
        const transport = createTransport();

        // Send email
        const mailOptions = {
            from: process.env.EMAIL_FROM || '"Auth Server" <noreply@auth-server.com>',
            to,
            subject,
            html,
            text: html.replace(/<[^>]*>/g, ''), // Simple plaintext version
        };

        const info = await transport.sendMail(mailOptions);

        // Log email URL in development (Ethereal)
        if (process.env.NODE_ENV === 'development') {
            console.log(`Preview URL: ${nodemailer.getTestMessageUrl(info)}`);
        }

        return info;
    } catch (error) {
        console.error('Error sending email:', error);
        throw new AppError('Failed to send email', 500);
    }
};

/**
 * Send verification email
 * @param {string} to - Recipient email address
 * @param {string} token - Verification token
 * @returns {Promise<Object>} Email send info
 */
export const sendVerificationEmail = async (to, token) => {
    const verificationUrl = `${process.env.API_URL}/api/auth/verify-email/${token}`;

    return sendEmail({
        to,
        subject: 'Verify Your Email Address',
        template: 'email-verification',
        data: {
            verificationUrl,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@auth-server.com',
            year: new Date().getFullYear(),
        },
    });
};

/**
 * Send reset password email
 * @param {string} to - Recipient email address
 * @param {string} token - Reset token
 * @returns {Promise<Object>} Email send info
 */
export const sendResetPasswordEmail = async (to, token) => {
    // Frontend URL for password reset
    const resetUrl = `${process.env.CLIENT_URL}/reset-password?token=${token}`;

    return sendEmail({
        to,
        subject: 'Reset Your Password',
        template: 'reset-password',
        data: {
            resetUrl,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@auth-server.com',
            expiryHours: process.env.JWT_RESET_PASSWORD_EXPIRATION
                ? parseInt(process.env.JWT_RESET_PASSWORD_EXPIRATION) / 60 / 60
                : 1, // Default to 1 hour if not specified
            year: new Date().getFullYear(),
        },
    });
};

/**
 * Send account unlock email
 * @param {string} to - Recipient email address
 * @param {string} token - Unlock token
 * @returns {Promise<Object>} Email send info
 */
export const sendAccountUnlockEmail = async (to, token) => {
    const unlockUrl = `${process.env.API_URL}/api/auth/unlock-account/${token}`;

    return sendEmail({
        to,
        subject: 'Unlock Your Account',
        template: 'account-unlock',
        data: {
            unlockUrl,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@auth-server.com',
            year: new Date().getFullYear(),
        },
    });
};

/**
 * Send password changed notification
 * @param {string} to - Recipient email address
 * @returns {Promise<Object>} Email send info
 */
export const sendPasswordChangedEmail = async (to) => {
    return sendEmail({
        to,
        subject: 'Your Password Has Been Changed',
        template: 'password-changed',
        data: {
            supportEmail: process.env.SUPPORT_EMAIL || 'support@auth-server.com',
            loginUrl: `${process.env.CLIENT_URL}/login`,
            year: new Date().getFullYear(),
        },
    });
};

/**
 * Send new device login notification
 * @param {string} to - Recipient email address
 * @param {Object} data - Login data
 * @param {string} data.device - Device information
 * @param {string} data.location - Location information
 * @param {string} data.ip - IP address
 * @param {Date} data.time - Login time
 * @returns {Promise<Object>} Email send info
 */
export const sendLoginNotificationEmail = async (to, data) => {
    return sendEmail({
        to,
        subject: 'New Login Detected',
        template: 'login-notification',
        data: {
            ...data,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@auth-server.com',
            accountUrl: `${process.env.CLIENT_URL}/account/security`,
            year: new Date().getFullYear(),
        },
    });
};

export default {
    sendEmail,
    sendVerificationEmail,
    sendResetPasswordEmail,
    sendAccountUnlockEmail,
    sendPasswordChangedEmail,
    sendLoginNotificationEmail,
};