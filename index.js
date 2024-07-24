// Import express
const express = require('express');
const morgan = require('morgan');
const mongoose = require('mongoose');
require('dotenv').config();
const indexrouter = require('./route/index')
const session = require('express-session');
const passport = require('passport');
const cors = require('cors');


// Create an Express application
const app = express();
app.use(morgan('dev'));
app.use(express.json());
// Define a port number
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

// connect to the database
mongoose.connect(MONGODB_URI)
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));
const allowedOrigins = [
    'https://frontend-blog-j6vih5v6d-mayorwise001s-projects.vercel.app',
    'http://localhost:3002'
  ];
  
  const corsOptions = {
    origin: function (origin, callback) {
      // Allow requests with no origin, like mobile apps or curl requests
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        const msg = 'The CORS policy for this site does not allow access from the specified origin.';
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    credentials: true
  };
  
  app.use(cors(corsOptions));


     
// Define a route for the root URL
app.use('/api', indexrouter);

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
