import { Request, Response } from "express";
import { registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { hashPassword } from "../../libs/hash";
import jwt from "jsonwebtoken";
import { sendMail } from "../../libs/email";

function getAppUrl() {
  return process.env.APP_URL || `http://locahost:${process.env.PORT}`;
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid Data!",
        error: result.error.flatten(),
      });
    }

    const { name, email, password } = result.data;

    const normalizedEmail = email.toLocaleLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(409).json({
        message: `Email is already is in use! Please try another email.`,
      });
    }

    const passwordHash = await hashPassword(password);

    const newlyCreatedUser = await User.create({
      email: normalizedEmail,
      passwordHash: passwordHash,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    const verifyToken = jwt.sign(
      {
        sub: newlyCreatedUser.id,
      },
      process.env.JWT_ACCESS_SECRET as string,
      {
        expiresIn: "1d",
      }
    );

    const verifyUrl = `${getAppUrl}/auth/verify-email?token=${verifyToken}`;

    await sendMail(
      newlyCreatedUser.email,
      "Verify You Email",
      `<p>Please verify your email by clicking this link:</p>
       <p><a href=${verifyUrl}>Verify Url</a></p>
      `
    );

    return res.status(201).json({
      message: "User registered.",
      user: {
        id: newlyCreatedUser.id,
        email: newlyCreatedUser.email,
        role: newlyCreatedUser.role,
        isEmailValid: newlyCreatedUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string | undefined;

  if (!token) {
    res.status(400).json({
      message: "Verification token is missing.",
    });
  }
}
