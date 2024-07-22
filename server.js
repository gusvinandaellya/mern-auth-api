import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import User from "./models/User.js";
import bcrypt from 'bcrypt';
import cors from 'cors';
import jwt from 'jsonwebtoken';

const secret = 'secret123';

await mongoose.connect('mongodb://localhost:27017/express-auth');
mongoose.connection.on('error', console.error.bind(console, 'connection error:'));

const app = express();
app.use(cookieParser());
app.use(bodyParser.json({extended: true}));
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.get('/', (req, res) => {
    res.send('Server Running');
});

app.get('/user', (req, res) => {
    const payload = jwt.verify(req.cookies.token, secret);
    User.findById(payload.id)
      .then(userInfo => {
        res.json({id: userInfo._id,email: userInfo.email});
    });
});

app.post('/register', (req, res) => {
    const {email, password} = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = new User({email, password:hashedPassword});
    user.save().then(userInfo => {
        jwt.sign({id: userInfo._id, email: userInfo.email}, secret, (err, token) => {
            if (err) {
                res.status(500).send('Error signing token');
            } else {
                res.cookie('token', token).json({id: userInfo._id, email: userInfo.email});
            }
        })
    });
});

app.post('/login', (req, res) => {
   const {email, password} = req.body;
   User.findOne({email}).then(userInfo => {
       const passOk = bcrypt.compareSync(password, userInfo.password);
       if (passOk) {
           jwt.sign({id: userInfo._id, email: userInfo.email}, secret, (err, token) => {
               if (err) {
                   res.status(500).send('Error signing token');
               } else {
                   res.cookie('token', token).json({id: userInfo._id, email: userInfo.email});
               }
           })
       } else {
            res.status(401).send('Invalid credentials');
       }
   });
});

app.post('/logout', (req, res) => {
    res.cookie('token', '', { expires: new Date(0) }).send('Logged out');
});

app.listen(4000);