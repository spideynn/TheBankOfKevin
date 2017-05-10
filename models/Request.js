var crypto = require('crypto');
var bcrypt = require('bcrypt-nodejs');
var mongoose = require('mongoose');

var schemaOptions = {
  timestamps: true,
  toJSON: {
    virtuals: true
  }
};

var requestSchema = new mongoose.Schema({
  date: Date,
  amount: Number,
  read: Boolean,
  approved: Boolean,
  denyReason: String
}, schemaOptions);


module.exports = requestSchema;
