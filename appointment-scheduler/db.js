const mysql = require('mysql2');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Mac2025!',
  database: 'appointment_db'
}).promise();

module.exports = db;