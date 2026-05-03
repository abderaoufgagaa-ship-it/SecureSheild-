SecureShield: Role-Based Access Control (RBAC) API
Mini Project II: SecureShield A Python-based Flask application that simulates a secure backend system. This project implements a robust authentication flow using JSON Web Tokens (JWT) and an Access Control mechanism that restricts features based on user roles (Admin vs. User).
🚀 Features
Part 1: Authentication & Identity
Secure Password Storage: Passwords are salted and hashed using flask-bcrypt before being stored in a local JSON database.
JWT Issuance: Successful logins generate a JWT containing the user's username and role.
Token Validation: A custom decorator intercepts requests to protected routes, ensuring a valid, non-expired JWT is present in the Authorization header.
Part 2: Access Control & Authorization
Role-Based Routing:
GET /profile: Accessible by both User and Admin roles.
DELETE /user/<id>: Accessible strictly by the Admin role.
Token Revocation (Blacklisting): A /logout endpoint that invalidates tokens before their natural expiry by adding them to a blacklist.
Defensive Logging: A middleware that logs every "Unauthorized" (403 Forbidden) attempt to security.log, including the timestamp, the user, and the attempted action.
🛠️ Tech Stack
Framework: Flask
Security & Auth: PyJWT, Flask-Bcrypt
Database: Local JSON simulation (users.json, blacklist.json)
📦 Installation & Setup
