import mongoose from "mongoose";

export async function connectToDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI!);
    console.log("✅ MongoDB connection is successfully established!");
  } catch (error) {
    console.error(`❎ MongoDB connection error!`);
    process.exit(1);
  }
}
