const express = require('express');
const router = express.Router();
const asyncHandler = require('express-async-handler');
const db = require('../db'); // We will create this db connection file next

// @desc    Get all tasks for a user
// @route   GET /api/tasks
// @access  Private
router.get('/', asyncHandler(async (req, res) => {
  const [tasks] = await db.query('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
  res.json(tasks);
}));

// @desc    Create a new task
// @route   POST /api/tasks
// @access  Private
router.post('/', asyncHandler(async (req, res) => {
  const { title, description, priority, status } = req.body;
  if (!title) {
    res.status(400);
    throw new Error('Title is required');
  }
  const sql = 'INSERT INTO tasks (user_id, title, description, priority, status) VALUES (?, ?, ?, ?, ?)';
  const [result] = await db.query(sql, [req.user.id, title, description || '', priority || 'Moderate', status || 'Not Started']);
  const [newTask] = await db.query('SELECT * FROM tasks WHERE id = ?', [result.insertId]);
  res.status(201).json(newTask[0]);
}));

// @desc    Update a task
// @route   PUT /api/tasks/:id
// @access  Private
router.put('/:id', asyncHandler(async (req, res) => {
    const { title, description, priority, status } = req.body;
    const { id } = req.params;

    const [tasks] = await db.query('SELECT * FROM tasks WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (tasks.length === 0) {
        res.status(404);
        throw new Error('Task not found');
    }

    const sql = 'UPDATE tasks SET title = ?, description = ?, priority = ?, status = ? WHERE id = ?';
    await db.query(sql, [title, description, priority, status, id]);

    const [updatedTask] = await db.query('SELECT * FROM tasks WHERE id = ?', [id]);
    res.json(updatedTask[0]);
}));

// @desc    Delete a task
// @route   DELETE /api/tasks/:id
// @access  Private
router.delete('/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const [tasks] = await db.query('SELECT * FROM tasks WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (tasks.length === 0) {
        res.status(404);
        throw new Error('Task not found');
    }

    await db.query('DELETE FROM tasks WHERE id = ?', [id]);
    res.json({ message: 'Task removed successfully' });
}));

module.exports = router;