const crypto = require('crypto');

const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { validationResult } = require('express-validator');

const User = require('../models/user');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

exports.getLogin = (req, res, next) => {
  // actully we don't use req.flash('error'); as we don't set it in post request
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
    },
    validationErrors: [],
  });
};

exports.getSignup = (req, res, next) => {
  // actully we don't use req.flash('error'); as we don't set it in post request
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: '',
    },
    validationErrors: [],
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
      },
      validationErrors: errors.array(),
    });
  }

  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage: 'Invalid email or password.',
          oldInput: {
            email: email,
            password: password,
          },
          validationErrors: [],
        });
      }
      bcrypt
        .compare(password, user.password)
        .then(doMatch => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              res.redirect('/');
            });
          }
          return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: 'Invalid email or password.',
            oldInput: {
              email: email,
              password: password,
            },
            validationErrors: [],
          });
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login');
        });
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword,
      },
      validationErrors: errors.array(),
    });
  }

  bcrypt
    .hash(password, 12)
    .then(hashedPassword => {
      const user = new User({
        email: email,
        password: hashedPassword,
        cart: { items: [] },
      });
      return user.save();
    })
    .then(result => {
      res.redirect('/login');

      return transporter.sendMail({
        to: email,
        from: process.env.GMAIL_USER,
        subject: 'Signup succeeded!',
        html: `
          <h1>✔ You successfully signed up in our shop!</h1>
          <a href="${process.env.BASE_URL}">Click here to go to the shop</a>
        `,
      });
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    res.redirect('/');
  });
};

exports.getReset = (req, res, next) => {
  return res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: req.flash('error')[0] ?? null,
    oldInput: req.flash('oldInput')[0] ?? null,
    message: req.flash('message')[0],
  });
};

exports.postReset = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      req.flash('error', 'Email not found');
      req.flash('oldInput', { email: req.body.email });
      return res.redirect('/reset');
    }

    // generate token
    crypto.randomBytes(32, async (err, buffer) => {
      if (err) {
        req.flash('error', 'An error happened please try again');
        req.flash('oldInput', { email: req.body.email });
        return res.redirect('/reset');
      }
      const token = buffer.toString('hex');

      user.resetToken = token;
      user.resetTokenExpiration = Date.now() + 3600000;

      await user.save();

      await transporter.sendMail({
        from: process.env.GMAIL_USER,
        to: user.email,
        subject: 'Shop Password Reset',
        html: `
          <h2> You have requested password reset please click the link to continue </h2>
          <a href="${process.env.BASE_URL}/reset/${token}"> Click here to continue </a>
        `,
      });

      req.flash(
        'message',
        'Eamil was sent. Chech your email for the reset link'
      );
      return res.redirect('/reset');
    });
  } catch (err) {
    next(err);
  }
};

exports.getNewPassword = async (req, res, next) => {
  try {
    const token = req.params.token;
    const user = await User.findOne({ resetToken: token });
    if (!user) {
      const error = new Error('There is no such page');
      error.httpStatusCode = 404;
      throw error;
    }
    if (user.resetTokenExpiration < Date.now())
      throw new Error(
        'This reset password link is out of date you need to reset your password again'
      );

    return res.render('auth/new-password', {
      path: '/new-password',
      pageTitle: 'New Password',
      userId: user._id,
      passwordToken: token,
      errorMessage: req.flash('error')[0] ?? null,
      oldInput: req.flash('oldInput')[0] ?? null,
      errorParams: req.flash('errorParams')[0] ?? null,
    });
  } catch (err) {
    next(err);
  }
};

exports.postNewPassword = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash(
      'error',
      errors
        .array()
        .map(e => e.msg)
        .join(' ')
    );
    req.flash('oldInput', {
      password: req.body.password,
      confirmPassword: req.body.confirmPassword,
    });

    const errorParams = {};
    errors.array().forEach(e => {
      errorParams[e.path] = true;
    });
    req.flash('errorParams', errorParams);
    return res.redirect('/reset/' + req.body.passwordToken);
  }

  const passwordToken = req.body.passwordToken;
  const userId = req.body.userId;
  const newPassword = req.body.password;

  try {
    const user = await User.findOne({ resetToken: passwordToken, _id: userId });
    if (!user) throw new Error("Error happened. Data doesn't match");
    if (user.resetTokenExpiration < Date.now())
      throw new Error(
        'This reset password link is out of date you need to reset your password again'
      );

    const hashed = await bcrypt.hash(newPassword, 12);
    user.password = hashed;
    user.resetToken = null;
    user.resetTokenExpiration = null;
    await user.save();
    return res.redirect('/login');
  } catch (err) {
    next(err);
  }
  // TEST expiration date
  // http://localhost:3000/reset/c1fd24dffca521c820f52c2111f4e142cf7262c26fd6ed1c7997a802d917b49e
};
// exports.getReset = (req, res, next) => {
//   let message = req.flash('error');
//   if (message.length > 0) {
//     message = message[0];
//   } else {
//     message = null;
//   }
//   res.render('auth/reset', {
//     path: '/reset',
//     pageTitle: 'Reset Password',
//     errorMessage: message,
//   });
// };

// exports.postReset = (req, res, next) => {
//   crypto.randomBytes(32, (err, buffer) => {
//     if (err) {
//       console.log(err);
//       return res.redirect('/reset');
//     }
//     const token = buffer.toString('hex');
//     User.findOne({ email: req.body.email })
//       .then(user => {
//         if (!user) {
//           req.flash('error', 'No account with that email found.');
//           return res.redirect('/reset');
//         }
//         user.resetToken = token;
//         user.resetTokenExpiration = Date.now() + 3600000;
//         return user.save();
//       })
//       .then(result => {
//         res.redirect('/');
//         transporter.sendMail({
//           to: req.body.email,
//           from: 'shop@node-complete.com',
//           subject: 'Password reset',
//           html: `
//             <p>You requested a password reset</p>
//             <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p>
//           `,
//         });
//       })
//       .catch(err => {
//         const error = new Error(err);
//         error.httpStatusCode = 500;
//         return next(error);
//       });
//   });
// };

// exports.getNewPassword = (req, res, next) => {
//   const token = req.params.token;
//   User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
//     .then(user => {
//       let message = req.flash('error');
//       if (message.length > 0) {
//         message = message[0];
//       } else {
//         message = null;
//       }
//       res.render('auth/new-password', {
//         path: '/new-password',
//         pageTitle: 'New Password',
//         errorMessage: message,
//         userId: user._id.toString(),
//         passwordToken: token,
//       });
//     })
//     .catch(err => {
//       const error = new Error(err);
//       error.httpStatusCode = 500;
//       return next(error);
//     });
// };

// exports.postNewPassword = (req, res, next) => {
//   const newPassword = req.body.password;
//   const userId = req.body.userId;
//   const passwordToken = req.body.passwordToken;
//   let resetUser;

//   User.findOne({
//     resetToken: passwordToken,
//     resetTokenExpiration: { $gt: Date.now() },
//     _id: userId,
//   })
//     .then(user => {
//       resetUser = user;
//       return bcrypt.hash(newPassword, 12);
//     })
//     .then(hashedPassword => {
//       resetUser.password = hashedPassword;
//       resetUser.resetToken = undefined;
//       resetUser.resetTokenExpiration = undefined;
//       return resetUser.save();
//     })
//     .then(result => {
//       res.redirect('/login');
//     })
//     .catch(err => {
//       const error = new Error(err);
//       error.httpStatusCode = 500;
//       return next(error);
//     });
// };
