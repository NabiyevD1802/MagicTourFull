const User = require('../models/userModel');
const catchErrorAsync = require('../utility/catchAsync');
const jwt = require('jsonwebtoken');
const AppError = require('../utility/appError');
const bcrypt = require('bcryptjs');

const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const signup = catchErrorAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    photo: req.body.photo,
    passwordConfirm: req.body.passwordConfirm,
    passwordChangedDate: req.body.passwordChangedDate,
  });

  const token = createToken(newUser._id);

  res.status(200).json({
    status: 'success',
    token: token,
    data: newUser,
  });
});

const login = catchErrorAsync(async (req, res, next) => {
  // 1) Email bilan password borligini tekshirish

  const { email, password } = { ...req.body };

  if (!email || !password) {
    return next(new AppError('Email yoki passwordni kiriting! Xato!!!', 401));
  }

  // 2) Shunaqa odam bormi yuqmi shuni tekshirish
  const user = await User.findOne({ email }).select('password');
  if (!user) {
    return next(
      new AppError('Bunday user mavjud emas. Iltimos royxatdan uting!', 404)
    );
  }

  // 3) password tugri yokin notugriligini tekshirish
  const tekshirHashga = async (oddiyPassword, hashPassword) => {
    const tekshir = await bcrypt.compare(oddiyPassword, hashPassword);
    return tekshir;
  };

  if (!(await tekshirHashga(password, user.password))) {
    return next(
      new AppError(
        'Sizning parol yoki loginingiz xato! Iltimos qayta urinib kuring!',
        401
      )
    );
  }
  // 4) JWT token yasab berish
  const token = createToken(user._id);

  // 5) Response qaytarish
  res.status(200).json({
    status: 'success',
    token: token,
  });
});

const protect = catchErrorAsync(async (req, res, next) => {
  // 1) Token bor yuqligini headerdan tekshirish
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) {
    return next(new AppError('Siz tizimga kirishingiz shart!'));
  }
  // 2) Token ni tekshirish Serverniki bilan clientnikini solishtirish

  console.log(jwt.verify(token, process.env.JWT_SECRET));

  const tokencha = jwt.verify(token, process.env.JWT_SECRET);

  // 3) Token ichidan idni olib databasedagi userni topamiz.
  const user = await User.findById(tokencha.id);
  if (!user) {
    return next(
      new AppError(
        'Bunday user mavjud emas! Iltimos tizimga qayta kiring!',
        401
      )
    );
  }

  // 4) Agar parol o'zgargan bo'lsa tokenni amal qilmasligini tekshirish

  if (user.passwordChangedDate) {
    if (tokencha.iat < user.passwordChangedDate.getTime() / 1000) {
      return next(
        new AppError(
          'Siz tokeningz yaroqsiz! Iltimos qayta tizimga kiring!',
          401
        )
      );
    }
  }

  req.user = user;

  next();
});

const role = (roles) => {
  return catchErrorAsync(async (req, res, next) => {
    // 1) User ni roleni Database dan olamiz

    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('Siz bu amaliyotni bajarish huquqiga ega emassiz!', 404)
      );
    }
    next();
  });
};

const forgotPassword = catchErrorAsync(async (req, res, next) => {
  // 1) Email bor yo'qligini tekshirish

  if (!req.body.email) {
    return;
  }
  // 2) Userni email orqali Database dan tekshirish
  // 3) ResetToken yaratib berish
  // 4) Email ga jo'natish ResetTokenni
});

module.exports = { signup, login, protect, role, forgotPassword };
