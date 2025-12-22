import { Request, Response, Router } from "express";
import requireAuth from "../middlewares/requireAuth";
import requireRole from "../middlewares/requireRole";
import { User } from "../models/user.model";

const router = Router();

router.get(
  "/user",
  requireAuth,
  requireRole("admin"),
  async (_req: Request, res: Response) => {
    try {
      const user = await User.find(
        {},
        {
          email: 1,
          role: 1,
          isEmailVerified: 1,
          createdAt: 1,
        }
      ).sort({ createdAt: -1 });

      const result = user.map((u) => ({
        id: u.id,
        email: u.email,
        role: u.role,
        isEmailVerified: u.isEmailVerified,
      }));

      return res.json({
        users: result,
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        message: "Internal server error.",
      });
    }
  }
);

export default router;
