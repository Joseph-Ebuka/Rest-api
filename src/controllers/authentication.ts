import { createUser, getUserByEmail } from "../db/users";
import express from "express";
import { random, authentication } from "../helpers";

export const register = async (
  req: express.Request,
  res: express.Response
): Promise<any> => {
  try {
    const { email, password, username } = req.body;

    if (!email || !password || !username) {
      return res.sendStatus(400);
    }

    const existingUser = await getUserByEmail(email);
    if (existingUser) {
      return res.sendStatus(400);
    }

    const salt = random();
    const user = await createUser({
      email,
      username,
      authentication: {
        salt,
        password: authentication(salt, password).toString('hex'),
      },
    });

    return res.status(200).json(user).end();
  } catch (error) {
    console.log(error);
    return res.sendStatus(400);
  }
};
export const login = async (
  req: express.Request,
  res: express.Response
): Promise<any> => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.sendStatus(400);
    }

    const user = await getUserByEmail(email).select(
      "+authentication.salt +authentication.password"
    );

    if (!user) {
      return res.status(403).json({ error: "User not found" });
    }

    const expectedHash = authentication(user.authentication.salt, password);
    console.log(expectedHash.toString('hex'));
    console.log(user.authentication.password);
    if (user.authentication.password !== expectedHash.toString('hex')) {
      return res.status(403).json({ error: "Invalid password" });
    }

    const salt = random();
    user.authentication.sessionToken = authentication(
      salt,
      user._id.toString()
    ).toString("base64");

    await user.save();

    res.cookie("EBUKA-AUTH", user.authentication.sessionToken, {
      domain: "localhost",
      path: "/",
    });
    return res.status(200).json(user).end();
  } catch (error) {
    console.log(error);
    res.sendStatus(400);
  }
};
