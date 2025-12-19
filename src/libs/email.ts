import transport from "../configs/smtp";

export async function sendMail(to: string, subject: string, html: string) {
  const from = process.env.EMAIL_FROM || "no-reply@example.com";

  await transport.sendMail({ from, to, subject, html });
}
