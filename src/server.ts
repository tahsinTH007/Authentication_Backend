import { createServer } from "node:http";
import app from "./app";
import { connectToDB } from "./configs/db";
import dotenv from "dotenv";

dotenv.config();

async function startServer() {
  await connectToDB();

  const server = createServer(app);

  server.listen(process.env.PORT, () => {
    console.log(`✅ Server is listing at PORT:${process.env.PORT}`);
  });
}

startServer().catch((err) => {
  console.error(`❎ Error while starting the server`, err);
  process.exit(1);
});
