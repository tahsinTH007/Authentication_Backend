import QRcode from "qrcode";

const otpAuthUrl = process.argv[2];

if (!otpAuthUrl) {
  throw new Error("Pass OTP auth url as arguments");
}

async function main() {
  await QRcode.toFile("totp.png", otpAuthUrl);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
