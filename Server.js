
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');
const fs = require('fs');


const { body, validationResult } = require('express-validator'); // Import express-validator

const app = express();
const port = 3001;
const JWT_SECRET = 'your_secret_key';

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/signupDB')
.then(() => {
  console.log('Connected to MongoDB');
  seedAdminAccounts();  // ✅ Call the function after successful connection
})
  .catch(err => console.error('MongoDB connection error:', err));

  app.use(express.static(path.join(__dirname, 'public')));


// User Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  username: { type: String, required: true, unique: true, trim: true },
  age: { type: Number, required: true },
  salary: { type: Number, default: 0 },
  country: { type: String, required: true },
  phone: { type: String, required: true },
  relation: { type: String, enum: ['single', 'married'], required: true },
  children: { type: Number, default: 0 },
  gender: { type: String, enum: ['male', 'female'], required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' }
});
const User = mongoose.model('SignUp', userSchema,'signups');

// Expense Schema
const expenseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'SignUp', required: true },
  type: String,
  product: String,
  cost: Number,
  date: Date,
});
const Expense = mongoose.model('Expense', expenseSchema);

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const Admin = mongoose.model('Admin', adminSchema);

async function seedAdminAccounts() {
  const admins = [
    { 
      email: 'bahajaghoob10@gmail.com', 
      username: 'bahaa', 
      password: 'BahaaPass',
    },
    { 
      email: 'Deemaabed.16@gmail.com', 
      username: 'deema', 
      password: 'DeemaPass',
    },
    { 
      email: 'aseelrana56@gmail.com', 
      username: 'Aseel', 
      password: 'AseelPass',
    }
  ];

  for (const admin of admins) {
    const existingAdmin = await Admin.findOne({ email: admin.email });
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(admin.password, 10);
      await Admin.create({
        email: admin.email,
        username: admin.username,
        password: hashedPassword,
      });
      console.log(`Admin account created: ${admin.email}`);
    }
  }
}

// Call the function once

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(403).json({ error: 'Access Denied' });

  const token = authHeader.split(' ')[1];
  console.log('Token received:', token); // Debug log

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification failed:', err); // Debug log
      return res.status(403).json({ error: 'Invalid Token' });
    }
    req.user = user;
    next();
  });
}

app.get('/SignUp.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'SignUp.html'));
});
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
      const token = bearerHeader.split(' ')[1];
      jwt.verify(token, JWT_SECRET, (err, authData) => {
          if (err) {
              res.status(403).json({ error: "Authorization failed" });
          } else {
              req.authData = authData;
              next();
          }
      });
  } else {
      res.status(403).json({ error: "Authorization failed" });
  }
}

// ======= Existing Routes =======

// Serve SignIn.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'FirstScreen.html'));
});

app.get('/api/gender-ratio', async (req, res) => {
  try {
    const maleCount = await User.countDocuments({ gender: 'male' });
    const femaleCount = await User.countDocuments({ gender: 'female' });

    res.json({ male: maleCount, female: femaleCount });
  } catch (error) {
    console.error('Error fetching gender ratio:', error);
    res.status(500).send('Error fetching gender ratio');
  }
});

app.put('/changePassword', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
      const user = await User.findById(req.user.userId);

      if (!user) {
          return res.status(404).send('User not found.');
      }

      // ✅ Check if the current password is correct
      const isPasswordCorrect = await bcrypt.compare(currentPassword, user.password);
      if (!isPasswordCorrect) {
          return res.status(400).send('Current password is incorrect.');
      }

      // ✅ Validate new password strength
      const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*]).{6,}$/;
      if (!passwordRegex.test(newPassword)) {
          return res.status(400).send('New password must be at least 6 characters long and include at least one letter, one number, and one symbol.');
      }

      // ✅ Hash the new password and save it
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedNewPassword;
      await user.save();

      res.status(200).send('Password updated successfully.');
  } catch (error) {
      console.error('Error changing password:', error);
      res.status(500).send('Error changing password.');
  }
});

// Route to get Age distribution
app.get('/api/age-distribution', async (req, res) => {
  try {
    const ageGroups = await User.aggregate([
      {
        $bucket: {
          groupBy: "$age",
          boundaries: [0, 18, 25, 35, 45, 60, 100],
          default: "Unknown",
          output: { count: { $sum: 1 } }
        }
      }
    ]);

    res.json(ageGroups);
  } catch (error) {
    console.error('Error fetching age distribution:', error);
    res.status(500).send('Error fetching age distribution');
  }
});

app.get('/api/registration-over-time', async (req, res) => {
  try {
    const registrations = await User.aggregate([
      {
        $group: {
          _id: { $month: "$createdAt" },  // Group by month
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }  // Sort by month
    ]);
    res.json(registrations);
  } catch (error) {
    console.error('Error fetching registration data:', error);
    res.status(500).send('Error fetching registration data');
  }
});



app.get('/api/income-expenses', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const expenses = await Expense.find({ userId: req.user.userId });

    let monthlyExpenses = Array(12).fill(0);
    expenses.forEach(expense => {
      const month = new Date(expense.date).getMonth();
      monthlyExpenses[month] += expense.cost;
    });

    res.json({ salary: user.salary, expenses: monthlyExpenses });
  } catch (error) {
    console.error('Error fetching income-expense data:', error);
    res.status(500).send('Error fetching income-expense data');
  }
});

app.get('/api/expense-categories', authenticateToken, async (req, res) => {
  try {
    const categories = await Expense.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.userId) } },
      { $group: { _id: "$type", total: { $sum: "$cost" } } }
    ]);

    res.json(categories);
  } catch (error) {
    console.error('Error fetching expense categories:', error);
    res.status(500).send('Error fetching expense categories');
  }
});

app.get('/api/country-distribution', async (req, res) => {
  try {
    const distribution = await User.aggregate([
      { $group: { _id: "$country", count: { $sum: 1 } } }
    ]);

    res.json(distribution);
  } catch (error) {
    console.error('Error fetching country distribution:', error);
    res.status(500).send('Error fetching country distribution');
  }
});

app.get('/api/age-spending', authenticateToken, async (req, res) => {
  try {
    const spending = await User.aggregate([
      {
        $lookup: {
          from: "expenses",
          localField: "_id",
          foreignField: "userId",
          as: "expenses"
        }
      },
      {
        $group: {
          _id: "$age",
          totalSpent: { $sum: { $sum: "$expenses.cost" } }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    res.json(spending);
  } catch (error) {
    console.error('Error fetching age spending data:', error);
    res.status(500).send('Error fetching age spending data');
  }
});

app.get('/api/relation-spending', authenticateToken, async (req, res) => {
  try {
    const spending = await User.aggregate([
      {
        $lookup: {
          from: "expenses",
          localField: "_id",
          foreignField: "userId",
          as: "expenses"
        }
      },
      {
        $group: {
          _id: "$relation",
          totalSpent: { $sum: { $sum: "$expenses.cost" } }
        }
      }
    ]);

    res.json(spending);
  } catch (error) {
    console.error('Error fetching relationship spending data:', error);
    res.status(500).send('Error fetching relationship spending data');
  }
});



// Login Route
app.post('/signIn', async (req, res) => {
  const { email, password } = req.body;
  try {
    console.log('Email received:', email);

    let user = await Admin.findOne({ email });
    let isAdmin = true;

    if (!user) {
      user = await User.findOne({ email });
      isAdmin = false;
    }

    if (!user) {
      console.log('User not found');

      return res.status(400).json({ error: 'User not found.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Incorrect password.' });
    }

    const tokenPayload = {
      userId: user._id,
      email: user.email,
      role: isAdmin ? 'admin' : 'user',
      salary: isAdmin ? 0 : user.salary  // Include salary, even if it's 0 for admins
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      token,
      redirectUrl: isAdmin ? '/ManagerScreen.html' : '/Money.html',
      salary: tokenPayload.salary
    });

  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/ManagerScreen.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ManagerScreen.html'));
});

app.get('/getUserData', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json(user);
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'Failed to fetch user data.' });
  }
});

// Save Expense Route
app.post('/addExpense', authenticateToken, async (req, res) => {
  const { type, product, cost, date } = req.body;

  try {
    if (!type || !product || !cost || !date) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const expense = new Expense({
      userId: req.user.userId,
      type,
      product,
      cost,
      date
    });

    await expense.save();
    res.status(201).json({ message: 'Expense saved successfully.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error saving expense.' });
  }
});

// Fetch Expenses Route
app.get('/getExpenses', authenticateToken, async (req, res) => {
  
  try {
    const expenses = await Expense.find({ userId: req.user.userId });
    res.json(expenses);
  } catch (error) {
    console.error('Error fetching expenses:', error);
    res.status(500).json({ error: 'Failed to load expenses.' });
  }
});

// ======= Place the Delete and Update Routes Here =======

// Delete Expense Route
app.delete('/deleteExpense/:id', authenticateToken, async (req, res) => {
  try {
    const expenseId = req.params.id;
    await Expense.findByIdAndDelete(expenseId);
    res.status(200).send('Expense deleted successfully');
  } catch (error) {
    console.error('Error deleting expense:', error);
    res.status(500).send('Failed to delete expense');
  }
});

// Update Expense Route
app.put('/updateExpense/:id', authenticateToken, async (req, res) => {
  const { product, cost } = req.body;

  try {
    await Expense.findByIdAndUpdate(req.params.id, { product, cost });
    res.status(200).send('Expense updated successfully');
  } catch (error) {
    console.error('Error updating expense:', error);
    res.status(500).send('Failed to update expense');
  }
});

app.put('/updateUserData', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, username, age, salary, country, phone, relation, children, gender } = req.body;

    await User.findByIdAndUpdate(req.user.userId, {
      firstName,
      lastName,
      username,
      age,
      salary,
      country,
      phone,
      relation,
      children,
      gender
    });

    res.status(200).send('User data updated successfully');
  } catch (error) {
    console.error('Error updating user data:', error);
    res.status(500).send('Failed to update user data');
  }
});



// ======= Server Listener =======















// Define schema and model
const signUpSchema = new mongoose.Schema({
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    username: { type: String, required: true, unique: true, trim: true },
    age: { type: Number, required: true },
    salary: { type: Number, default: 0 },
    country: { type: String, required: true },
    phone: { type: String, required: true },
    relation: { type: String, enum: ['single', 'married'], required: true },
    children: { type: Number, default: 0 },
    gender: { type: String, enum: ['male', 'female'], required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' }
});

const SignUp = mongoose.models.SignUp || mongoose.model('SignUp', signUpSchema);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

// Route to serve the SignUp page
app.get('/signup', (req, res) => {
  console.log('Received data:', req.body);
    res.sendFile(path.join(__dirname, 'SignUp.html'));
  });
 


// Sign Up Route
app.post('/signUp', async (req, res) => {
  console.log('Request body:', req.body);  // Log the incoming request

  const {
      firstName, lastName, username, age, salary, country,
      phone, relation, children, gender, interests, email, password
  } = req.body;

  if (!firstName || !lastName || !username || !age || !salary || !country || !phone || !relation || !gender || !email || !password) {
      return res.status(400).json({ error: 'Please fill in all required fields.' });
  }

  try {
      const existingUser = await User.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
          return res.status(400).json({ error: 'Username or email already exists.' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = new User({
          firstName, lastName, username, age: parseInt(age), salary: parseFloat(salary),
          country, phone, relation, children: parseInt(children) || 0,
          gender, interests, email, password: hashedPassword
      });

      await newUser.save()
          .then((savedUser) => {
              console.log('✅ User saved successfully:', savedUser);
              res.status(200).json({ message: 'Registration successful!' });
          })
          .catch((saveError) => {
              console.error('❌ Error saving user:', saveError);
              res.status(500).json({ error: 'Failed to save user.', details: saveError.message });
          });

  } catch (error) {
      console.error('❌ Unexpected error:', error);
      res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Debugging Middleware
app.use((req, res, next) => {
  console.log(`Request received: ${req.url}`);
  next();
});

// Serve the HTML file for the root route
app.get('/', (req, res) => {
    const htmlPath = path.join(__dirname, 'FirstScreen.html');

  if (fs.existsSync(htmlPath)) {
    res.sendFile(htmlPath);
  } else {
    console.error(`File not found: ${htmlPath}`);
    res.status(404).send('ManagerScreen.html not found');
  }
});

// Connect to MongoDB

// User Schema and Model

// Routes

app.use(express.static(path.join(__dirname, 'public')));

app.post('/create-account', authenticateToken, async (req, res) => {
  console.log('Request body:', req.body);
  console.log('Authenticated User:', req.user); // Added to check the user's role from the token

  const {
    firstName,
    lastName,
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
    password
  } = req.body;

  // Validate required fields
  if (!firstName || !lastName || !username || !age || !country || !phone || !relation || !gender || !email || !password) {
    return res.status(400).json({ error: 'Please fill in all required fields.' });
  }

  try {
    console.log('Create Account Request:', req.body);
    // Check if username or email already exists
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user with "role: user"
    const newUser = new User({
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
      interests,
      email,
      password: hashedPassword,
      role: 'user'  // Ensure the role is always 'user'
    });

    await newUser.save();
    console.log('New user created:', newUser);

    res.status(200).json({ message: 'User account created successfully!' });
  } catch (error) {
    console.error('Error creating user account:', error);
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  }
});


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
    // Check if the user with the provided email exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send({ error: 'Email not found' });
    }

    // Compare the provided password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send({ error: 'Incorrect password' });
    }

    // Delete the user if email and password are correct
    await User.deleteOne({ email });
    res.send({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).send({ error: 'Failed to delete account', details: error.message });
  }
});
// update account
app.post('/update-account', async (req, res) => {
  const { email, password, newPassword, ...updates } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and current password are required.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User with this email not found.' });
    }

    // Check if the provided current password matches the user's password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Incorrect current password.' });
    }

    // Update the password if a new one is provided and validate it
    if (newPassword) {
      const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({ error: 'New password must be at least 8 characters long and include letters, numbers, and symbols.' });
      }

      user.password = await bcrypt.hash(newPassword, 10);
    }

    // Update other fields
    for (const key in updates) {
      if (updates[key]) {
        user[key] = updates[key];
      }
    }

    await user.save();
    res.status(200).json({ message: 'Account updated successfully!' });

  } catch (error) {
    console.error('Error updating account:', error);
    res.status(500).json({ error: 'An unexpected error occurred while updating the account.' });
  }
});




// find account
app.post('/find-account', async (req, res) => {
  const { username } = req.body;

  try {
    if (!username) {
      return res.status(400).json({ error: 'Username is required.' });
    }

    // Find the user by username
    const user = await User.findOne({ username: username.trim() });

    if (!user) {
      return res.status(404).json({ error: 'Username not found.' });
    }

    // Return user details (exclude sensitive information like password)
    res.status(200).json({
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      age: user.age,
      salary: user.salary,
      country: user.country,
      phoneNumber: user.phone,
      relation: user.relation,
      children: user.children,
      gender: user.gender,
      interests: user.interests,
    });
  } catch (err) {
    console.error('Error finding user:', err);
    res.status(500).json({ error: 'Error finding user.', details: err.message });
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


// Add Admin
app.post('/add-admin', async (req, res) => {
  const { email, username, password } = req.body;
  try {
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin with this email already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({ email, username, password: hashedPassword });
    await newAdmin.save();

    res.status(201).json({ message: 'Admin added successfully!' });
  } catch (error) {
    console.error('Error adding admin:', error);
    res.status(500).json({ error: 'Failed to add admin.' });
  }
});

// Remove Admin
app.post('/remove-admin', async (req, res) => {
  const { email } = req.body;
  try {
    const admin = await Admin.findOneAndDelete({ email });
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found.' });
    }
    res.status(200).json({ message: 'Admin removed successfully!' });
  } catch (error) {
    console.error('Error removing admin:', error);
    res.status(500).json({ error: 'Failed to remove admin.' });
  }
});

// Update Admin (update password)
app.post('/update-admin', async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedPassword;
    await admin.save();

    res.status(200).json({ message: 'Admin password updated successfully!' });
  } catch (error) {
    console.error('Error updating admin password:', error);
    res.status(500).json({ error: 'Failed to update admin password.' });
  }
});

app.get('/api/all-users', authenticateToken, async (req, res) => {
  try {
    // Fetch all users except their password
    const users = await User.find().select('-password');
    res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching all users:', error);
    res.status(500).send('Failed to fetch users.');
  }
});




// Start Server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
  });



