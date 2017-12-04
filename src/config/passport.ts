import * as passport from "passport";
import * as request from "request";
import * as passportLocal from "passport-local";
import * as jwt from "jsonwebtoken";

// import { User, UserType } from '../models/User';
import { default as User } from "../models/User";
import { Request, Response, NextFunction } from "express";

const LocalStrategy = passportLocal.Strategy;

/**
 * Sign in using Email and Password.
 */
passport.use(new LocalStrategy({ usernameField: "email" }, (email, password, done) => {
  User.findOne({ email: email.toLowerCase() }, (err, user: any) => {
    if (err) { return done(err); }
    if (!user) {
      return done(undefined, false, { message: `Email ${email} not found.` });
    }
    user.comparePassword(password, (err: Error, isMatch: boolean) => {
      if (err) { return done(err); }
      if (isMatch) {
        return done(undefined, user);
      }
      return done(undefined, false, { message: "Invalid email or password." });
    });
  });
}));

/**
 * Generate json web token
 */
export let signToken = (tokenObject: object) => {
  return jwt.sign(tokenObject, process.env.TOKEN_SECRET, { expiresIn: "1h" });
};

/**
 * Oauth Required middleware.
 */
export let isAuthenticated = (req: Request, res: Response, next: NextFunction) => {

  // check header or url parameters or post parameters for token
  const token = req.body.token || req.query.token || req.headers["x-access-token"];

  // decode token
  if (token) {
    // verifies secret and checks exp
    jwt.verify(token, process.env.TOKEN_SECRET, function (err: Error, tokenObject: object) {
      if (err) {
        return res.json({ status: "failed", message: "Failed to authenticate token." });
      } else {
        // if everything is good, save to request for use in other routes
        req.app.set("tokenObject", tokenObject);
        next();
      }
    });
  } else {
    // if there is no token
    // return an error
    res.json({ status: "failed", message: "Please Provide Token" });
  }
};
