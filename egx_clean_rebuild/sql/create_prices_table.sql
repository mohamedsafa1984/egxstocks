-- Prices table (foundation for future automation/scoring)
-- SQLite

CREATE TABLE IF NOT EXISTS prices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  symbol TEXT NOT NULL,
  date TEXT NOT NULL,              -- ISO date: YYYY-MM-DD
  open REAL,
  high REAL,
  low REAL,
  close REAL,
  volume REAL,
  source TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(symbol, date)
);
