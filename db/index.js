import sqlite from "./sqlite.js";
import postgres from "./postgres.js";

const DIALECT = (process.env.DB_DIALECT || "sqlite").trim().toLowerCase();
const isPostgres = DIALECT === "postgres" || DIALECT === "pg";

const driver = isPostgres ? postgres : sqlite;

// Unified helpers used by server.js
const run = driver.run;
const get = driver.get;
const all = driver.all;
const closeDb = driver.close;
const dbInfo = driver.info;

export { run, get, all, closeDb, dbInfo, isPostgres };
