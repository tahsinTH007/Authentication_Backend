import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

if (
  !process.env.SMTP_HOST ||
  !process.env.SMTP_USER ||
  !process.env.SMTP_PASS
) {
  throw new Error("SMTP environment variables are required!");
}

const host = process.env.SMTP_HOST;
const port = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587;
const user = process.env.SMTP_USER;
const pass = process.env.SMTP_PASS;

const transport = nodemailer.createTransport({
  host,
  port,
  secure: false,
  auth: {
    user,
    pass,
  },
});

export default transport;
