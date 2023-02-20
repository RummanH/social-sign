const { Router } = require('express');

const userRouter = require('./users.router');

const router = Router();

router.use('/users', userRouter);

module.exports = router;
