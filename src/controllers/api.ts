"use strict";

import * as async from "async";
import * as request from "request";
import { Response, Request, NextFunction } from "express";


/**
 * GET /api
 * List of API examples.
 */
export let getApi = (req: Request, res: Response) => {
  res.json({ status: "success", response: { text: req.app.get("tokenObject") } });
};