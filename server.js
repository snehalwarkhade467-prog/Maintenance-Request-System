
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const path = require('path');
const Complaint = require('./models/Complaint');
const User = require('./models/User');
const bcrypt = require('bcryptjs');

const app = express();

app.use(express.json());

app.use(session({
  name: 'connect.sid',
  secret: process.env.SESSION_SECRET || 'maintenance-dev-secret-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Check whether student/admin is logged in
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      message: 'Please login first.'
    });
  }

  next();
}

// Only admin can update or delete complaints
function requireAdmin(req, res, next) {
  if (req.session.userRole !== 'admin') {
    return res.status(403).json({
      message: 'Admin access required.'
    });
  }

  next();
}

// Home page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Dashboard: login required
app.get('/dashboard', requireLogin, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Maintenance Dashboard</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          background: #f3f6fb;
          padding: 30px;
          text-align: center;
        }
        main {
          max-width: 600px;
          margin: 40px auto;
          padding: 30px;
          background: white;
          border-radius: 12px;
          box-shadow: 0 4px 18px #00000012;
        }
        button {
          padding: 12px 24px;
          background: #2457d6;
          color: white;
          border: none;
          border-radius: 6px;
          cursor: pointer;
        }
      </style>
    </head>
    <body>
      <main>
        <h1>Maintenance System</h1>
        <h2>Welcome, ${escapeHtml(req.session.userName)}!</h2>
        <p>You are logged in successfully.</p>
        <p>Role: ${escapeHtml(req.session.userRole)}</p>
        <button onclick="logout()">Logout</button>
        <p id="message"></p>
      </main>

      <script>
        async function logout() {
          try {
            const response = await fetch('/logout', {
              method: 'POST'
            });

            const data = await response.json();

            if (response.ok) {
              window.location.href = '/login.html';
            } else {
              document.getElementById('message').textContent =
                data.message || 'Logout failed';
            }
          } catch (error) {
            document.getElementById('message').textContent =
              'Unable to connect to server';
          }
        }
      </script>
    </body>
    </html>
  `);
});

// Escape user-provided text before putting it in HTML
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

// Register student
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== 'string' ||
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      !name.trim() ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: 'Name, email and password are required.'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters.'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await User.findOne({
      email: normalizedEmail
    });

    if (existingUser) {
      return res.status(409).json({
        message: 'Email is already registered.'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      role: 'student'
    });

    return res.status(201).json({
      message: 'Registration successful!',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: 'Email is already registered.'
      });
    }

    console.error('Registration error:', error.message);

    return res.status(500).json({
      message: 'Registration failed.'
    });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: 'Email and password are required.'
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase()
    });

    if (!user) {
      return res.status(401).json({
        message: 'Invalid email or password.'
      });
    }

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {
      return res.status(401).json({
        message: 'Invalid email or password.'
      });
    }

    // Regenerate session after successful authentication
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session error:', err.message);
        return res.status(500).json({
          message: 'Unable to create login session.'
        });
      }

      req.session.userId = user._id.toString();
      req.session.userRole = user.role;
      req.session.userName = user.name;

      req.session.save((saveError) => {
        if (saveError) {
          console.error('Session save error:', saveError.message);
          return res.status(500).json({
            message: 'Unable to save login session.'
          });
        }

        return res.status(200).json({
          message: 'Login successful!',
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role
          }
        });
      });
    });
  } catch (error) {
    console.error('Login error:', error.message);

    return res.status(500).json({
      message: 'Login failed.'
    });
  }
});

// Logout
app.post('/logout', (req, res) => {
  if (!req.session) {
    return res.json({ message: 'Logout successful.' });
  }

  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        message: 'Logout failed.'
      });
    }

    res.clearCookie('connect.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: false
    });

    return res.json({
      message: 'Logout successful.'
    });
  });
});

// Submit a complaint: logged-in users only
app.post('/complaints', requireLogin, async (req, res) => {
  try {
    const complaint = new Complaint(req.body);
    await complaint.save();

    return res.status(201).json({
      message: 'Complaint submitted successfully!',
      complaint
    });
  } catch (error) {
    return res.status(400).json({
      message: 'Error submitting complaint',
      error: error.message
    });
  }
});

// View all complaints: logged-in users only
app.get('/complaints', requireLogin, async (req, res) => {
  try {
    const complaints = await Complaint.find().sort({
      createdAt: -1
    });

    return res.status(200).json(complaints);
  } catch (error) {
    return res.status(500).json({
      message: 'Error fetching complaints'
    });
  }
});

// View one complaint: logged-in users only
app.get('/complaints/:id', requireLogin, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({
        message: 'Invalid complaint ID.'
      });
    }

    const complaint = await Complaint.findById(req.params.id);

    if (!complaint) {
      return res.status(404).json({
        message: 'Complaint not found.'
      });
    }

    return res.status(200).json(complaint);
  } catch (error) {
    return res.status(500).json({
      message: 'Error fetching complaint.'
    });
  }
});

// Update complaint status: admin only
app.patch(
  '/complaints/:id',
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({
          message: 'Invalid complaint ID.'
        });
      }

      const allowedStatuses = [
        'Pending',
        'In Progress',
        'Resolved'
      ];

      const { status } = req.body;

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          message: 'Invalid status.',
          allowedStatuses
        });
      }

      const complaint = await Complaint.findByIdAndUpdate(
        req.params.id,
        { $set: { status } },
        { new: true, runValidators: true }
      );

      if (!complaint) {
        return res.status(404).json({
          message: 'Complaint not found.'
        });
      }

      return res.status(200).json({
        message: 'Complaint status updated successfully!',
        complaint
      });
    } catch (error) {
      return res.status(400).json({
        message: 'Error updating complaint.'
      });
    }
  }
);

// Delete complaint: admin only
app.delete(
  '/complaints/:id',
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({
          message: 'Invalid complaint ID.'
        });
      }

      const complaint = await Complaint.findByIdAndDelete(
        req.params.id
      );

      if (!complaint) {
        return res.status(404).json({
          message: 'Complaint not found.'
        });
      }

      return res.status(200).json({
        message: 'Complaint deleted successfully!'
      });
    } catch (error) {
      return res.status(500).json({
        message: 'Error deleting complaint.'
      });
    }
  }
);

// Connect to MongoDB and start server
const PORT = process.env.PORT || 3000;

if (!process.env.MONGODB_URI) {
  console.error('Please add MONGODB_URI to your .env file.');
  process.exit(1);
}

mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected successfully!');

    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('MongoDB connection failed:', error.message);
    process.exit(1);
  });
