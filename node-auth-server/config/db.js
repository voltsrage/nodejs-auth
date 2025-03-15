import mongoose from "mongoose";

const connectDB = async () => {
    try {
        // Set mongoose connection options
        mongoose.set('strictQuery', false);

        console.log('Connecting to MongoDB...', process.env.MONGODB_URI);
        // Connect to MongoDB
        const connection = await mongoose.connect(process.env.MONGODB_URI, {

        });
        console.log(`MongoDB connected: ${connection.connection.host}`);
    }
    catch (error) {
        console.error(`Error connecting to MongoDB: ${error.message}`);
        process.exit(1);
    }
}

export default connectDB;