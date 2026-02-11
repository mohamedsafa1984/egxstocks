# EGX Clean Rebuild (One Server)

## Run
1) Install Node.js (LTS)
2) Open terminal in this folder
3) `npm install`
4) `node server.js`
5) Open: http://localhost:5000

## Notes
- Uses SQLite file `data.sqlite` (created automatically). No Postgres needed.
- Signup/Login works.

## Admin (UI DB Management)
- Default Admin account (created automatically on first run):
  - Email: admin@egx.local
  - Password: admin123456
- You can change these defaults via environment variables:
  - ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_USERNAME

- Admin can (from UI):
  - Create users (role user/admin)
  - Delete users (cannot delete self or CEO)
  - Promote/Demote users (user <-> admin)
  - Hide/Unhide recommendations
  - Edit/Delete recommendations
- Recommendations:
  - Public list: GET /api/recommendations
  - Add (requires login): POST /api/recommendations with Bearer token
