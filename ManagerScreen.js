const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const { body, validationResult } = require('express-validator'); // Import express-validator

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

// Debugging Middleware
app.use((req, res, next) => {
  console.log(`Request received: ${req.url}`);
  next();
});

// Serve the HTML file for the root route
app.get('/', (req, res) => {

  const htmlPath = path.join(__dirname, 'ManagerScreen.html');
  if (fs.existsSync(htmlPath)) {
    res.sendFile(htmlPath);
  } else {
    console.error(`File not found: ${htmlPath}`);
    res.status(404).send('ManagerScreen.html not found');
  }
});

// Connect to MongoDB
mongoose
  .connect('mongodb://127.0.0.1:27017/signupDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Connected to MongoDB (signupDB)'))
  .catch((err) => {
    console.error('Database connection error:', err.message);
    process.exit(1);
  });

// User Schema and Model
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  username: { type: String, unique: true, required: true }, // Username must be unique
  age: Number,
  salary: Number,
  country: String,
  phoneNumber: String,
  relation: String,
  children: Number,
  gender: String,
  interests: [String],
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }, // Plain-text password (for testing only)
});

const User = mongoose.model('User', userSchema);

// Routes

app.post(
  '/create-account',
  [
    body('firstName')
      .isAlpha()
      .withMessage('First name must contain only letters')
      .custom((value) => !/\s/.test(value))
      .withMessage('First name must be a single word'),
    body('lastName')
      .optional({ nullable: true })
      .isAlpha()
      .withMessage('Last name must contain only letters'),
    body('username')
      .isAlphanumeric()
      .withMessage('Username must contain only letters and numbers'),
    body('age')
      .isInt({ min: 1 })
      .withMessage('Age must be a positive number'),
    body('salary')
      .isFloat({ min: 0 })
      .withMessage('Salary must be a non-negative number'),
    body('phoneNumber')
      .isLength({ min: 10, max: 10 })
      .withMessage('Phone number must be exactly 10 digits'),
    body('email')
      .isEmail()
      .withMessage('Invalid email format'),
    body('password')
      .isLength({ min: 8 })
      .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
      .withMessage('Password must include letters, numbers, and symbols, and be at least 8 characters long.'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.error('Validation errors:', errors.array()); // Debugging: Log validation errors
      return res.status(400).json({ errors: errors.array() });
    }

    console.log('Password received:', req.body.password); // Debugging: Log the password input

    try {
      const existingUser = await User.findOne({ username: req.body.username });
      if (existingUser) {
        return res.status(400).send({ error: 'Username is already taken. Please choose another one.' });
      }

      const user = new User(req.body);
      await user.save();
      res.status(201).send({ message: 'Account created successfully' });
    } catch (err) {
      res.status(400).send({ error: 'Failed to create account', details: err });
    }
  }
);

//test password
app.post(
  '/test-password',
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
    .withMessage('Password must include letters, numbers, and symbols, and be at least 8 characters long.'),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.error('Password validation errors:', errors.array()); // Log errors for debugging
      return res.status(400).json({ errors: errors.array() });
    }
    res.status(200).send({ message: 'Password is valid.' });
  }
);


// Delete Account
app.post('/delete-account', async (req, res) => {
  const { email, password } = req.body;

  try {
    console.log('Received email:', email);
    console.log('Received password:', password);

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      console.log('User not found');
      return res.status(404).send({ error: 'Account not found' });
    }

    console.log('User found:', user);

    // Directly compare the provided password with the stored password
    if (password !== user.password) {
      return res.status(401).send({ error: 'Invalid email or password' });
    }

    // Delete the user
    await User.deleteOne({ email });
    console.log('User deleted successfully');
    res.send({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error('Error deleting account:', err);
    res.status(500).send({ error: 'Error deleting account', details: err });
  }
});
// update account
app.post('/update-account', async (req, res) => {
  const { email, password, newPassword, ...updates } = req.body;

  console.log("Incoming request for update:", req.body); // Log request body

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.error("User not found:", email);
      return res.status(404).json({ error: "User not found" });
    }
    console.log("User found:", user);

    if (user.password !== password) {
      console.error("Password mismatch for user:", email);
      return res.status(401).json({ error: "Incorrect password" });
    }

    if (newPassword) {
      const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (!passwordRegex.test(newPassword)) {
        console.error("Invalid password format:", newPassword);
        return res.status(400).json({ error: "Password validation failed" });
      }

      user.password = newPassword;
      console.log("Password updated to:", newPassword);
    }

    for (const key in updates) {
      if (updates[key]) {
        user[key] = updates[key];
        console.log(`Updated ${key} to:`, updates[key]);
      }
    }

    await user.save()
      .then(() => console.log("User successfully saved:", user))
      .catch((err) => console.error("Error during save:", err));

    res.status(200).json({ message: "Account updated successfully!" });
  } catch (error) {
    console.error("Unexpected error during update:", error);
    res.status(500).json({ error: "An unexpected error occurred while updating the account." });
  }
});




// find account
app.post('/find-account', async (req, res) => {
  const { username } = req.body;
  console.log('Username received:', username, typeof username);

  if (!username) {
    return res.status(400).send({ error: 'Username is required.' });
  }

  try {
    // Ensure the username is treated as a string and trim whitespace
    const user = await User.findOne({ username: username.trim() });
console.log('Database query result:', user);

    if (!user) {
      console.log('User not found in database');
      return res.status(404).send({ error: 'User not found.' });
    }

    console.log('User found:', user);
    return res.status(200).send({
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      age: user.age,
      salary: user.salary,
      country: user.country,
      phoneNumber: user.phoneNumber,
      relation: user.relation,
      children: user.children,
      gender: user.gender,
      interests: user.interests,
    });
  } catch (err) {
    console.error('Error finding user:', err);
    res.status(500).send({ error: 'Error finding user.', details: err.message });
  }
});



// Common logic for finding an account
async function handleFindAccount(res, username) {
  if (!username) {
    return res.status(400).send({ error: 'Username is required.' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).send({ error: 'User not found.' });
    }

    // Respond with user details
    res.status(200).send({
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      age: user.age,
      salary: user.salary,
      country: user.country,
      phoneNumber: user.phoneNumber,
      relation: user.relation,
      children: user.children,
      gender: user.gender,
      interests: user.interests,
    });
  } catch (err) {
    console.error('Error finding user:', err);
    res.status(500).send({ error: 'Error finding user', details: err });
  }
}

// Admin Schema
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const Admin = mongoose.model('Admin', adminSchema); // This will create the `Admins` collection in the `signupDB`

// Routes

// Add Admin
app.post('/add-admin', [
  body('email').isEmail().withMessage('Invalid email format'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
    .withMessage('Password must include letters, numbers, and symbols.'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password } = req.body;

    // Ensure no duplicate admin exists
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin with this email already exists.' });
    }

    const admin = new Admin({ email, password });
    await admin.save();
    res.status(201).json({ message: 'Admin added successfully!' });
  } catch (err) {
    console.error('Error adding admin:', err);
    res.status(500).json({ error: 'Failed to add admin.', details: err });
  }
});


// Delete Admin
app.post('/delete-admin', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find and delete the admin
    const admin = await Admin.findOneAndDelete({ email, password });
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found or incorrect credentials.' });
    }

    res.json({ message: 'Admin deleted successfully.' });
  } catch (err) {
    console.error('Error deleting admin:', err);
    res.status(500).json({ error: 'Failed to delete admin.', details: err });
  }
});

// Update Admin
app.post('/update-admin', async (req, res) => {
  const { email, password, newPassword } = req.body;

  try {
    // Find the admin by email and password
    const admin = await Admin.findOne({ email, password });
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found or incorrect credentials.' });
    }

    // Update the password if a new password is provided
    if (newPassword) {
      admin.password = newPassword;
    }

    await admin.save();
    res.json({ message: 'Admin updated successfully.' });
  } catch (err) {
    console.error('Error updating admin:', err);
    res.status(500).json({ error: 'Failed to update admin.', details: err });
  }
});

/** Sign in !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */


// Start Server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

