import mongoose from "mongoose";

const tokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        index: true,
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    type: {
        type: String,
        enum: ['refresh', 'resetPassword', 'verifyEmail', 'verifySms'],
        required: true,
    },
    expires: {
        type: Date,
        required: true,
    },
    blacklisted: {
        type: Boolean,
        default: false,
    },
    userAgent: {
        type: String,
    },
    ipAddress: {
        type: String,
    },
},
    {
        timestamps: true,
    });

// Create compound index on token and type
tokenSchema.index({ token: 1, type: 1 });

// Create TTL index on expires field
tokenSchema.index({ expires: 1 }, { expireAfterSeconds: 0 });

const Token = mongoose.model('Token', tokenSchema);

export default Token;