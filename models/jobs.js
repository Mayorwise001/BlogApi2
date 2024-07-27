// models/Job.js
const mongoose = require('mongoose');

const JobSchema = new mongoose.Schema({
    jobTitle: { type: String, required: true },
    jobDescription: { type: String, required: true },
    deadline: { type: Date, required: true },
    postedBy: { type: String, required: true },
    published: { type: Boolean, default: false },
    // category: { type: String, required: true },
    category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
    createdDate: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Job', JobSchema);
