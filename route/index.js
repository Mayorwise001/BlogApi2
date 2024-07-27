const express = require('express')
const router = express.Router();
const User = require('../models/adminuser'); // Adjust the path if needed
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const session = require("express-session");
const homeData = require('../config/homeData')
const jwt = require('jsonwebtoken');
const secretKey = 'okay'; 
const Token = require('../models/token');
const Job = require('../models/jobs')
const Category = require('../models/category')
const mongoose = require('mongoose');


router.use(passport.initialize());
router.use(session({ secret: "cats", resave: true, saveUninitialized: true }));
router.use(passport.session());

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
}

const verifyToken = async (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, secretKey);
        const tokenRecord = await Token.findOne({ token });

        if (!tokenRecord) {
            return res.status(401).json({ message: 'Invalid token' });
        }

        req.userId = decoded.id;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
};


// POST route to register a new user
router.post('/register', async (req, res) => {
    const {firstName, lastName, email, password } = req.body;

    // Validate input
    if ( !firstName || !lastName || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    const username = `${firstName}${lastName}`;
    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.status(400).json({ error: 'Username is already taken' });
        }

        // Create a new user
        const newUser = new User({ username, firstName, lastName, email, password});
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Register Users here

router.post('/register2', async (req, res) => {
    const { username, email, password } = req.body;
  
    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
  
    try {
      // Check if the user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }
  
      // Create a new user
      const newUser = new User({
        username,
        email,
        password,
      });
  
      // Save the user to the database
      await newUser.save();
  
      // Generate a JWT token
      const token = jwt.sign(
        { userId: newUser._id, username: newUser.username },
        process.env.secretKey,
        { expiresIn: '1h' }
      );
  
      res.status(201).json({ token, user: { id: newUser._id, username: newUser.username, email: newUser.email } });
    } catch (error) {
      console.error('Error registering user:', error);
      res.status(500).json({ error: 'Server error' });
    }
  });
  











// Code to login
router.post('/login', (req, res, next) => {
    passport.authenticate('local', async(err, user, info) => {
        if (err) return next(err);
        if (!user) return res.status(400).json({ message: 'wrong email or password' });

        req.logIn(user, async (err) => {
            if (err) return next(err);
            const token = jwt.sign({ id: user.id }, secretKey , { expiresIn: '1h' }); 
            try {
                await Token.create({ token, userId: user._id });
                return res.status(200).json({ message: 'Logged in successfully', user, token });
            } catch (error) {
                return res.status(500).json({ message: 'Error saving token' });
            }
        });
    })(req, res, next);
});

// POST route to change the user's password
router.post('/change-password',verifyToken,  async (req, res) => {
    const { email, oldPassword, newPassword } = req.body;

    // Validate input
    if (!email || !oldPassword || !newPassword) {
        return res.status(400).json({ error: 'Email, old password, and new password are required' });
    }
    try {
        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
   
        // Check if the old password matches
        const isMatch = await user.comparePassword(oldPassword);
        if (!isMatch) {
            return res.status(401).json({ error: 'Old password is incorrect' });
        }
        // Check if the old password matches
     
       
        // Update the password
        user.password = newPassword ;
        await user.save();

        res.status(200).json({ message: 'Password changed successfully' });
    } catch (err) {
        console.error('Error changing password:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Signout route
router.post('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to log out' });
        }
        res.status(200).json({ message: 'Logged out successfully' });
    });
});




router.get('/home', verifyToken, async (req, res, next) => { 
    return res.json({
        ...homeData,
        message: 'Your Login was successful'
      });
})

router.get('/check-auth', verifyToken, (req, res) => {
    res.status(200).json({ message: 'Authenticated' });
});

// Creatr Job Route
router.post('/add-job', verifyToken, async (req, res) => {
    const { jobTitle, jobDescription, deadline, category, published } = req.body;

    // Validate input
    if (!jobTitle || !jobDescription || !deadline || !category) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
              // Retrieve the user from the database using the token's userId
              const user = await User.findById(req.userId);
              if (!user) {
                  return res.status(404).json({ error: 'User not found' });
              }
        // Create a new job posting
        const newJob = new Job({
            jobTitle,
            jobDescription,
            deadline,
            postedBy: user.username, // Assuming req.userId is the username of the logged-in user
            published,
            category
        });

        await newJob.save();
        res.status(201).json({ message: 'Job posted successfully' });
    } catch (err) {
        console.error('Error posting job:', err);
        res.status(500).json({ error: 'Server error' });
    }
});


// GET route to fetch all published job postings
router.get('/published-jobs', verifyToken, async (req, res) => {
    try {
        // Find all published job postings
        const jobs = await Job.find({ published: true })
            .select('jobTitle jobDescription deadline postedBy') // Select only the necessary fields
            .populate('postedBy', 'username') // Populate the postedBy field with the username
            .populate('category', 'name') 
            .exec();

        // Format job descriptions to be brief
        const formattedJobs = jobs.map(job => ({
            jobTitle: job.jobTitle,
            jobDescription: job.jobDescription.length > 100 ? `${job.jobDescription.substring(0, 100)}...` : job.jobDescription,
            postedBy: job.postedBy,
            deadline: job.deadline,
            jobid: job._id,
            category: job.category
        }));

        res.status(200).json(formattedJobs);
    } catch (err) {
        console.error('Error fetching published jobs:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

router.get('/published-jobs2', async (req, res) => {
    try {
        // Find all published job postings
        const jobs = await Job.find({ published: true })
            .select('jobTitle jobDescription deadline postedBy') // Select only the necessary fields
            .populate('postedBy', 'username') // Populate the postedBy field with the username
            .populate('category', 'name') 
            .exec();

        // Format job descriptions to be brief
        const formattedJobs = jobs.map(job => ({
            jobTitle: job.jobTitle,
            jobDescription: job.jobDescription.length > 100 ? `${job.jobDescription.substring(0, 100)}...` : job.jobDescription,
            postedBy: job.postedBy,
            deadline: job.deadline,
            jobid: job._id,
            category: job.category.name
        }));

        res.status(200).json(formattedJobs);
    } catch (err) {
        console.error('Error fetching published jobs:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Display unpublished Jobs.

router.get('/unpublished-posts',  verifyToken, async (req, res) => {
    try {
        const unpublishedJobs = await Job.find({ published: false }, 'jobTitle jobDescription deadline postedBy published');
        res.status(200).json(unpublishedJobs);
    } catch (error) {
        console.error('Error fetching unpublished jobs:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route to update a job to published
router.post('/publish-job/:id', verifyToken, async (req, res) => {
    const jobId = req.params.id;
    try {
        const job = await Job.findById(jobId);
        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }

        job.published = true;
        await job.save();

        res.status(200).json({ message: 'Job published successfully' });
    } catch (error) {
        console.error('Error publishing job:', error);
        res.status(500).json({ error: 'Server error' });
    }
});


router.get('/job-details/:id',verifyToken, async (req, res) => {
    try {
        const jobId = req.params.id;

        // Validate the job ID
        if (!mongoose.Types.ObjectId.isValid(jobId)) {
            return res.status(400).json({ error: 'Invalid Job ID' });
        }

        const job = await Job.findById(jobId);
        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }
        res.json(job);
    } catch (error) {
        console.error('Error fetching job details:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/job-details2/:id', async (req, res) => {
    try {
        const jobId = req.params.id;

        // Validate the job ID
        if (!mongoose.Types.ObjectId.isValid(jobId)) {
            return res.status(400).json({ error: 'Invalid Job ID' });
        }

        const job = await Job.findById(jobId);
        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }
        res.json(job);
    } catch (error) {
        console.error('Error fetching job details:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.put('/job-details/:id', verifyToken, async (req, res) => {
    const { id } = req.params;
    const { jobTitle, jobDescription, deadline, postedBy } = req.body;

    try {
        const updatedJob = await Job.findByIdAndUpdate(
            id,
            {
                jobTitle,
                jobDescription,
                deadline,
                postedBy,
                category
            },
            { new: true }
        );

        if (!updatedJob) {
            return res.status(404).json({ message: 'Job not found' });
        }

        res.json(updatedJob);
    } catch (error) {
        console.error('Error updating job:', error);
        res.status(500).json({ message: 'Server error' });
    }
});


router.delete('/job-details/:id',verifyToken,async (req, res) => {
    try {
        const jobId = req.params.id;
        const deletedJob = await Job.findByIdAndDelete(jobId);

        if (!deletedJob) {
            return res.status(404).json({ message: 'Job not found' });
        }

        res.status(200).json({ message: 'Job deleted successfully' });
    } catch (error) {
        console.error('Error deleting job:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

router.get('/all-users', verifyToken, async (req, res) => {
    try {
        const users = await User.find({}, 'firstName lastName username'); // Fetch only necessary fields
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users', error });
    }
});

// DELETE /api/users/:id - Delete a user by ID
router.delete('/all-users/:id', verifyToken,async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }
        res.send({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).send({ message: 'Error deleting user', error });
    }
});


router.put('/:id/unpublish', verifyToken, async (req, res) => {
    try {
        const job = await Job.findById(req.params.id);
        if (!job) {
            return res.status(404).json({ message: 'Job not found' });
        }
        job.published = false;
        await job.save();
        res.json({ message: 'Job unpublished successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error unpublishing job', error });
    }
});


router.post('/addcategory', verifyToken, async (req, res) => {
    const { name } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Category name is required' });
    }

    try {
        const existingCategory = await Category.findOne({ name });
        if (existingCategory) {
            return res.status(400).json({ error: 'Category already exists' });
        }

        const newCategory = new Category({ name });
        await newCategory.save();
        res.status(201).json({ message: 'Category added successfully' });
    } catch (err) {
        console.error('Error adding category:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

router.get('/categories', verifyToken, async (req, res) => {
    try {
        const categories = await Category.find();
        res.status(200).json(categories);
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete a category by ID
router.delete('/delete-category/:id', verifyToken, async (req, res) => {
    const { id } = req.params;

    try {
        // Find the category by ID and delete it
        const category = await Category.findByIdAndDelete(id);

        if (!category) {
            return res.status(404).json({ error: 'Category not found' });
        }

        res.status(200).json({ message: 'Category deleted successfully' });
    } catch (err) {
        console.error('Error deleting category:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route to get all categories
router.get('/all-categories', verifyToken, async (req, res) => {
    try {
        const categories = await Category.find({});
        res.status(200).json(categories);
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ error: 'Server error' });
    }
});
router.get('/all-categories2', async (req, res) => {
    try {
        const categories = await Category.find({});
        res.status(200).json(categories);
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ error: 'Server error' });
    }
});




















// Configure Passport to use LocalStrategy for username and password authentication
passport.use(new LocalStrategy(
    { usernameField: 'email' }, // Use email as the username field
    async (email, password, done) => {
        try {
            // Find user by email
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: 'No user with that email' });
            }

            // Compare provided password with stored hashed password
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return done(null, false, { message: 'Password incorrect' });
            }

            // Authentication successful
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));



// Serialize user to store user ID in session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});
module.exports = router;