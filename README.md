# To-Do Dashboard API (Backend)

![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![Render](https://img.shields.io/badge/Render-46E3B7?style=for-the-badge&logo=render&logoColor=white)

This is the backend server for the Full-Stack To-Do Dashboard application. It is a secure RESTful API built with Node.js and Express. It is responsible for handling all business logic, user authentication, and database operations.

---

### 🔌 Live API Endpoint

The API is fully deployed on Render and is actively serving the live frontend application.

**Base URL:** **[https://todo-backend-api-vyp...onrender.com](https://todo-backend-api-vyp...onrender.com)**

---

### 🏛️ Project Architecture

This API was designed as the central hub of the application, serving data to the frontend client and managing the database connection.

*   **This Backend (API)**: Built with Node.js/Express and deployed on **Render**.
*   **Frontend Client**: **[https://github.com/Harshithk951/To-Do-Full-Stack](https://github.com/Harshithk951/To-Do-Full-Stack)**

`[React Frontend on Vercel] <--- HTTPS Requests ---> [Node/Express API on Render] <--- SSL Connection ---> [MySQL Database on Aiven]`

---

### 🔐 Security & Core Architecture Features

*   **JWT-Based Authentication**: Implemented a robust authentication system using `jsonwebtoken`. The `/login` endpoint issues a token, which is then required in the `Authorization` header for all protected API routes.
*   **Password Security**: User passwords are never stored in plaintext. I used the `bcryptjs` library to hash and salt all passwords upon registration, and to compare hashes during login.
*   **CORS Policy**: The `cors` middleware is configured with a strict whitelist, ensuring that API requests are only accepted from the deployed frontend URL (`process.env.FRONTEND_URL`).
*   **Secure Database Connection**: The MySQL connection is configured with `ssl: { ca: fs.readFileSync('./ca.pem')... }` for a secure, encrypted link to the Aiven cloud database, preventing SSL handshake errors.
*   **Environment-Driven Configuration**: All sensitive values (database credentials, JWT secret, URLs) are managed via environment variables and loaded using `dotenv` in local development. This follows the twelve-factor app methodology.

---

### 🛠️ Detailed Tech Stack

| Category                | Technology / Library      | Purpose                                                       |
| ----------------------- | ------------------------- | ------------------------------------------------------------- |
| **Core Framework**      | **Node.js, Express.js**   | Building the server, routing, and middleware infrastructure.  |
| **Database**            | **MySQL**                 | Relational database for storing user and to-do data.          |
| **Database Driver**     | **`mysql2`**              | Node.js client for connecting to the MySQL database.          |
| **Authentication**      | **`jsonwebtoken`**        | To sign and verify JSON Web Tokens for secure API access.     |
| **Password Hashing**    | **`bcryptjs`**            | For securely hashing user passwords.                          |
| **Middleware**          | **`cors`**                | To handle Cross-Origin Resource Sharing and secure the API.   |
| **Environment Variables** | **`dotenv`**              | To load environment variables from a `.env` file in development. |
| **Deployment**          | **Render**                | Cloud platform for deploying the backend service.             |
| **Version Control**     | **Git & GitHub**          | Source code management.                                       |

---

### 🗺️ API Endpoints

| Method   | Endpoint             | Description                           | Auth Required |
| :------- | :------------------- | :------------------------------------ | :-----------: |
| `POST`   | `/register`          | Registers a new user account.         |      No       |
| `POST`   | `/login`             | Authenticates a user, returns a JWT.  |      No       |
| `POST`   | `/forgot-password`   | Sends a password reset link to user.  |      No       |
| `GET`    | `/api/user/profile`  | Fetches profile of the logged-in user.|      Yes      |
| `PUT`    | `/api/user/profile`  | Updates profile of logged-in user.    |      Yes      |

---

### ⚙️ Local Setup and Installation

1.  **Clone the Repository:**
    ```sh
    git clone https://github.com/Harshithk951/todo-backend.git
    cd todo-backend
    ```
2.  **Install Dependencies:**
    ```sh
    npm install
    ```
3.  **Configure Environment Variables:**
    Create a file named `.env` in the root of the project. This is where you'll put your local database credentials and secrets.
    ```    # Database Connection
    DB_HOST=localhost
    DB_USER=root
    DB_PASSWORD=your_local_db_password
    DB_NAME=your_todo_database_name
    DB_PORT=3306

    # Security
    JWT_SECRET=a_very_long_and_secret_string_for_local_dev

    # CORS Configuration
    FRONTEND_URL=http://localhost:3000
    ```
4.  **Run the Server:**
    This will start the Express server, typically on port `3001`.
    ```sh
    npm start
    ```
