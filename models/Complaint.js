const mongoose = require('mongoose');

const complaintSchema = new mongoose.Schema({
  studentName: {
    type: String,
    required: true
  },

  roomNumber: {
    type: String,
    required: true
  },

  complaintType: {
    type: String,
    required: true
  },

  description: {
    type: String,
    required: true
  },

  status: {
    type: String,
    default: 'Pending'
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Complaint', complaintSchema);