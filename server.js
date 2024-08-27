const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const app = express();
const port = process.env.PORT || 3000;

mongoose.connect("mongodb://127.0.0.1:27017/backend").then(() => {
    console.log("Connected to MongoDB");
}).catch((error) => {
    console.error("Failed to connect to MongoDB", error);
});

const userSchema = new mongoose.Schema({
    name: { type: String, required: false },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const registerUser = mongoose.model('RegisterUser', userSchema);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Register.html'));
});

const isAuthenticated = async (req, res, next) => {
    const { token } = req.cookies;
    if (token) {
        const decoded = jwt.verify(token, "qwertyagon");
        req.user = await registerUser.findById(decoded._id);
        next();
    } else {
        res.redirect("/login");
    }
};

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
app.get('/user', isAuthenticated, (req, res) => {
    res.json({ name: req.user.name });
});


app.post('/logout', (req, res) => {
    res.clearCookie("token");
    res.redirect('/login');
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await registerUser.findOne({ email });

        if (!user) {
            return res.redirect('/register');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).send("Incorrect Password");

        const token = jwt.sign({ _id: user._id }, "qwertyagon", { expiresIn: '1h' });
        res.cookie("token", token, {
            httpOnly: true,
            expires: new Date(Date.now() + 60 * 60 * 1000),
        });

        res.redirect('/dashboard');
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).send('An error occurred during login');
    }
});

app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const Duplicatemail = registerUser.findOne({ email});
        if(!Duplicatemail){
            return res.status(409).send("Email already exists");
        }
        const hashPassword = await bcrypt.hash(password, 10);
        const newUser = new registerUser({ name, email, password: hashPassword });
        await newUser.save();
       
        const token = jwt.sign({ _id: newUser._id }, "qwertyagon", { expiresIn: '1h' });
        res.cookie("token", token, {
            httpOnly: true,
            expires: new Date(Date.now() + 60 * 60 * 1000),
        });

        res.redirect("/dashboard");
    } catch (error) {
        console.error("Error saving user:", error);
        res.status(500).send('Error occurred while saving user');
    }
});

app.listen(port, () => {
    console.log(`App listening on port ${port}`);
});
