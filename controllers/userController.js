const User = require('../models/userModel');
const catchErrorAsync = require('../utility/catchAsync');

const getAllUsers = catchErrorAsync(async (req, res, next) => {
  const users = await User.find();
  res.status(200).json({
    status: 'success',
    data: users,
  });
});

const addUser = (req, res) => {
  res.status(404).json({
    status: 'fail',
    message: 'This route has not created yet!',
  });
};
const updateUser = (req, res) => {
  res.status(404).json({
    status: 'fail',
    message: 'This route has not created yet!',
  });
};
const getUserById = (req, res) => {
  res.status(404).json({
    status: 'fail',
    message: 'This route has not created yet!',
  });
};
const deleteUser = catchErrorAsync(async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.status(200).json({
    status: 'success',
    message: 'user has been delete',
  });
});

module.exports = { getAllUsers, addUser, getUserById, updateUser, deleteUser };
