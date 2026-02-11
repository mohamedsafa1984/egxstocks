import pg from "pg";

const { Pool } = pg;

// Postgres connection options
// Prefer DATABASE_URL when available (common on cloud providers).
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || undefined,
  host: process.env.PGHOST || undefined,
  port: process.env.PGPORT ? Number(process.env.PGPORT) : undefined,
  user: process.env.PGUSER || undefined,
  password: process.env.PGPASSWORD || undefined,
  database: process.env.PGDATABASE || undefined,
  ssl: String(process.env.PGSSL || "").toLowerCase() === "true" ? { rejectUnauthorized: false } : undefined,
});

// Convert SQLite-style placeholders (?) into Postgres placeholders ($1, $2, ...)
function toPgPlaceholders(sql) {
  let i = 0;
  return String(sql).replace(/\?/g, () => {
    i += 1;
    return `$${i}`;
  });
}

async function run(sql, params = []) {
  const q = toPgPlaceholders(sql);
  const r = await pool.query(q, params);
  return r;
}

async function get(sql, params = []) {
  const r = await run(sql, params);
  return r.rows[0];
}

async function all(sql, params = []) {
  const r = await run(sql, params);
  return r.rows;
}

async function close() {
  await pool.end();
}

function info() {
  return { dialect: "postgres", hasDatabaseUrl: Boolean(process.env.DATABASE_URL) };
}

export default { pool, run, get, all, close, info };
