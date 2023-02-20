const http = require('http');
require('dotenv').config();

process.on('uncaughtException', (err) => {
  console.error(`Uncaught exception: ${err.name}, ${err.message}`);
  console.error('🤔 App is shutting down...');
  process.exit(1);
});

const app = require('./app');
const { mongoConnect } = require('./services/mongo');

const server = http.createServer(app);

const PORT = process.env.PORT || 5000;
(async () => {
  try {
    await mongoConnect();
    server.listen(PORT, () => {
      console.log(
        `✔ Server is listening on port: ${PORT} in ${process.env.NODE_ENV} environment.`
      );
    });
  } catch (err) {
    console.error(`🤔 There was an error starting the server ${err}`);
  }
})();

process.on('unhandledRejection', (err) => {
  console.error(`Unhandled rejection: ${err.name} ${err.message}`);
  console.error('🤔 App is shutting down...');
  server.close(() => {
    process.exit(1);
  });
});
