const { Router } = require('express');
const passport = require("passport");
const CLIENT_URL = "http://localhost:3000/";

const {
  httpSignupUser,
  httpLoginUser,
  httpForgotPassword,
  httpResetPassword,
  httpChangePassword,
  httpProtect,
} = require('../controllers/auth.controller');
const {
  httpUpdateMe,
  httpDeleteMe,
  httpGetAllUsers,
  httpGetOneUser,
  httpUpdateUser,
  httpDeleteUser,
} = require('../controllers/users.controller');
const catchAsync = require('../services/catchAsync');

const router = Router();

// Not RestFul for all users
router.route('/signup').post(catchAsync(httpSignupUser));
router.route('/login').post(catchAsync(httpLoginUser));
router.route('/forgotPassword').post(catchAsync(httpForgotPassword));
router.route('/resetPassword/:token').patch(catchAsync(httpResetPassword));

// For logged in users only

router.use(catchAsync(httpProtect));

router.route('/changePassword').patch(catchAsync(httpChangePassword));
router.route('/updateMe').patch(catchAsync(httpUpdateMe));
router.route('/deleteMe').delete(catchAsync(httpDeleteMe));

// RestFul routes may only used by administration
router.route('/').get(catchAsync(httpGetAllUsers));
router
  .route('/:_id')
  .get(catchAsync(httpGetOneUser))
  .patch(catchAsync(httpUpdateUser))
  .delete(catchAsync(httpDeleteUser));

router.get("/login/success", (req, res) => {
  if (req.user) {
    res.status(200).json({
      success: true,
      message: "successfull",
      user: req.user,
      //   cookies: req.cookies
    });
  }
});

router.get("/login/failed", (req, res) => {
  res.status(401).json({
    success: false,
    message: "failure",
  });
});

router.get("/logout", (req, res) => {
  req.logout();
  res.redirect(CLIENT_URL);
});

router.get("/google", passport.authenticate("google", { scope: ["profile"] }));

router.get(
  "/google/callback",
  passport.authenticate("google", {
    successRedirect: CLIENT_URL,
    failureRedirect: "/login/failed",
  })
);

router.get("/github", passport.authenticate("github", { scope: ["profile"] }));

router.get(
  "/github/callback",
  passport.authenticate("github", {
    successRedirect: CLIENT_URL,
    failureRedirect: "/login/failed",
  })
);

router.get("/facebook", passport.authenticate("facebook", { scope: ["profile"] }));

router.get(
  "/facebook/callback",
  passport.authenticate("facebook", {
    successRedirect: CLIENT_URL,
    failureRedirect: "/login/failed",
  })
);

module.exports = router;
