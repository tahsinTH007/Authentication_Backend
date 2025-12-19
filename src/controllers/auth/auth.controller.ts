import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { checkPassword, hashPassword } from "../../libs/hash";
import jwt from "jsonwebtoken";
import { sendMail } from "../../libs/email";
import { createAccessToken, createRefreshToken } from "../../libs/token";

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
      name: name,
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

  try {
    const payload = jwt.verify(
      token as string,
      process.env.JWT_ACCESS_SECRET as string
    ) as {
      sub: string;
    };

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    if (user.isEmailVerified) {
      return res.status(200).json({
        message: "Email is already verified.",
      });
    }

    user.isEmailVerified = true;

    await user?.save();

    res.json({
      message: "Email is now verified! You can log in.",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error.",
    });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid Data!",
        error: result.error.flatten(),
      });
    }

    const { email, password } = result.data;

    const normalizedEmail = email.toLocaleLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(400).json({
        message: "Invalid email or password",
      });
    }

    const comparePassword = await checkPassword(password, user.passwordHash);

    if (!comparePassword) {
      return res.status(400).json({
        message: "Invalid password",
      });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Please verify your email before log in.",
      });
    }

    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProduction = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Log in successfully.",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}
