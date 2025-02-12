const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

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
const User = mongoose.model('SignUp', userSchema);

// Expense Schema
const expenseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'SignUp', required: true },
  type: String,
  product: String,
  cost: Number,
  date: Date,
});
const Expense = mongoose.model('Expense', expenseSchema);

async function seedAdminAccounts() {
  const admins = [
    { 
      email: 'bahajaghoob10@gmail.com', 
      username: 'bahaa', 
      password: 'BahaaPass',
      firstName: 'Bahaa',
      lastName: 'Jaghoob',
      age: 20,
      salary: 3000,
      country: 'Palestine',
      phone: '123456789',
      relation: 'single',
      children: 0,
      gender: 'male'
    },
    { 
      email: 'Deemaabed.16@gmail.com', 
      username: 'deema', 
      password: 'DeemaPass',
      firstName: 'Deema',
      lastName: 'Abed',
      age: 20,
      salary: 3500,
      country: 'Palestine',
      phone: '987654321',
      relation: 'single',
      children: 0,
      gender: 'female'
    },
    { 
      email: 'aseelrana56@gmail.com', 
      username: 'Aseel', 
      password: 'AseelPass',
      firstName: 'Aseel',
      lastName: 'Abd Elhaq',
      age: 20,
      salary: 3500,
      country: 'Palestine',
      phone: '987654321',
      relation: 'single',
      children: 0,
      gender: 'female'
    }

  ];

  for (const admin of admins) {
    const existingAdmin = await User.findOne({ email: admin.email });
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(admin.password, 10);
      await User.create({
        email: admin.email,
        username: admin.username,
        password: hashedPassword,
        role: 'admin',
        firstName: admin.firstName,
        lastName: admin.lastName,
        age: admin.age,
        salary: admin.salary,
        country: admin.country,
        phone: admin.phone,
        relation: admin.relation,
        children: admin.children,
        gender: admin.gender
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

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Access Denied');
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid Token');
    console.log('Decoded User:', user);  // Debugging line
    req.user = user;
    next();
  });
}

// ======= Existing Routes =======

// Serve SignIn.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'SignIn.html'));
});

// Login Route
app.post('/signIn', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email: email });

    if (!user) {
      return res.status(400).send('User not found.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send('Incorrect password.');
    }

    // Include salary in the token payload
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role, salary: user.salary },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    if (user.role === 'admin') {
      res.json({ token, redirectUrl: '/adminDashboard.html', salary: user.salary });
    } else {
      res.json({ token, redirectUrl: '/Money.html', salary: user.salary });
    }

  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/getUserData', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');  // Exclude password

    if (!user) {
      return res.status(404).send('User not found.');
    }

    console.log("User Data Sent:", user);  // ✅ Debug log
    res.json(user);  // ✅ Send full user data
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Failed to fetch user data.');
  }
});

// Save Expense Route
app.post('/addExpense', authenticateToken, async (req, res) => {
  const { type, product, cost, date } = req.body;

  try {
    const expense = new Expense({
      userId: req.user.userId,
      type,
      product,
      cost,
      date
    });

    await expense.save();
    res.status(201).send('Expense saved successfully.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error saving expense.');
  }
});

// Fetch Expenses Route
app.get('/getExpenses', authenticateToken, async (req, res) => {
  try {
    const expenses = await Expense.find({ userId: req.user.userId });
    res.json(expenses);
  } catch (error) {
    console.error('Error fetching expenses:', error);
    res.status(500).send('Failed to load expenses.');
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
app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
