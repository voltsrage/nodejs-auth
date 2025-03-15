import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
    },
    password: {
        type: String,
        required: function () {
            // Password is required unless user is authenticated via OAuth
            return !this.oauthProvider;
        },
        minlength: 8,
    },
    username: {
        type: String,
        required: true,
        trim: true,
    },
    firstName: {
        type: String,
        trim: true,
    },
    lastName: {
        type: String,
        trim: true,
    },
    phoneNumber: {
        type: String,
        trim: true,
    },
    isEmailVerified: {
        type: Boolean,
        default: false,
    },
    isPhoneVerified: {
        type: Boolean,
        default: false,
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user',
    },
    oauthProvider: {
        type: String,
        enum: ['google', 'facebook', 'apple', 'line', null],
        default: null,
    },
    oauthId: {
        type: String,
        sparse: true,
    },
    passwordResetToken: String,
    passwordResetExpires: Date,
    emailVerificationToken: String,
    emailVerificationExpires: Date,
    lastLogin: Date,
    accountLocked: {
        type: Boolean,
        default: false,
    },
    loginAttempts: {
        type: Number,
        default: 0,
    },
    profilePicture: String,
},
    { timestamps: true });

// Create index for OAuth provider and ID
userSchema.index({ oauthProvider: 1, oauthId: 1 }, { unique: true, sparse: true });

// Pre-save middleware to hash password
userSchema.pre('save', async function (next) {
    const user = this;

    // Only hash the password if it's modified or new
    if (!user.isModified('password')) return next();

    try {
        // Generate salt
        const salt = await bcrypt.genSalt(10);

        // Hash password
        user.password = await bcrypt.hash(user.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Method to check if password is correct
userSchema.methods.comparePassword = async function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Method to check if account should be locked due to too many failed attempts
userSchema.methods.checkLoginAttempts = function (isValid) {
    // Reset login attempts if login is successful
    if (isValid) {
        this.loginAttempts = 0;
        this.accountLocked = false;
        return this.save();
    }

    // Increment login attempts
    this.loginAttempts += 1;

    // Lock account if login attempts exceed threshold (e.g., 5)
    if (this.loginAttempts >= 5) {
        this.accountLocked = true;
    }

    return this.save();
};

const User = mongoose.model('User', userSchema);

export default User;