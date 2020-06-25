const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const authenticate = require('../auth/authenticate-middleware.js');
const authRouter = require('../auth/auth-router.js');


const server = express();

server.use(helmet());
server.use(cors());
server.use(express.json());

server.use('/wave_suggester/auth', authRouter);

server.get("/", (req,res) => {
    res.status(200).json({ api: "up"})
});

module.exports = server;
