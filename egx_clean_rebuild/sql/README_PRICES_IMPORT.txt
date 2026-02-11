PRICES TABLE (future automation)

A SQLite table named `prices` is created automatically on first run.
This is only a DB foundation for future automation; the UI does not use it yet.

Columns
- symbol (TEXT): EGX ticker, e.g. COMI
- date (TEXT): YYYY-MM-DD
- open/high/low/close (REAL)
- volume (REAL)
- source (TEXT)
- created_at (TEXT)

Constraint
- UNIQUE(symbol, date)
