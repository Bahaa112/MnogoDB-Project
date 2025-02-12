const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const app = express();
const port = 3000;

// MongoDB connection
const mongoURI = 'mongodb://127.0.0.1:27017/signupDB';
mongoose.connect(mongoURI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB:', err));

// Define schema and model
const signUpSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  age: { type: Number, required: true },
  salary: { type: Number, required: true },
  country: { type: String, required: true },
  phone: { type: String, required: true },
  relation: { type: String, required: true },
  children: { type: Number, default: 0 },
  gender: { type: String, required: true },
  interests: { type: [String], required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  registeredAt: { type: Date, default: Date.now }  // Track when the user signed up
});

const SignUp = mongoose.model('SignUp', signUpSchema);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

// Route to serve the SignUp page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'SignUp.html'));
});

// Sign Up Route
app.post('/signUp', async (req, res) => {
  const {
    'first-name': firstName,
    'last-name': lastName,
    username,
    age,
    salary,
    country,
    phone,
    relation,
    children,
    gender,
    interests,
    email,
    password,
  } = req.body;

  // Password validation regex
  const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*]).{6,}$/;

  try {
    // Check if username already exists
    const existingUsername = await SignUp.findOne({ username });
    if (existingUsername) {
      return res.status(400).send(
        `<script>alert('Username already exists. Please choose a different one.'); window.location='/';</script>`
      );
    }

    // Check if email already exists
    const existingEmail = await SignUp.findOne({ email });
    if (existingEmail) {
      return res.status(400).send(
        `<script>alert('Email already exists. Please use a different email.'); window.location='/';</script>`
      );
    }

    // Validate password strength
    if (!passwordRegex.test(password)) {
      return res.status(400).send(
        `<script>alert('Password must be at least 6 characters long and include at least one letter, one number, and one symbol.'); window.location='/';</script>`
      );
    }

    // Hash the password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    // Validate that required fields are not empty
    if (!firstName || !lastName || !username || !email || !password || !gender) {
      return res.status(400).send(
        `<script>alert('Please fill in all required fields.'); window.location='/';</script>`
      );
    }

    // Save form data to MongoDB
    const newUser = new SignUp({
      firstName,
      lastName,
      username,
      age: parseInt(age),
      salary: parseFloat(salary),
      country,
      phone,
      relation,
      children: parseInt(children) || 0,
      gender,
      interests: Array.isArray(interests) ? interests : [interests],
      email,
      password: hashedPassword,  // Store hashed password
    });

    await newUser.save();
    console.log('New user saved:', newUser);
    res.send(
      `<script>alert('Form data saved to the database successfully!'); window.location='/';</script>`
    );
  } catch (error) {
    console.error('Error saving form data:', error);
    res.status(500).send(
      `<script>alert('An error occurred while saving form data. Please try again later.'); window.location='/';</script>`
    );
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
