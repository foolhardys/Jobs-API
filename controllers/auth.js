const User = require('../models/User')
const { StatusCodes } = require('http-status-codes')
const { BadRequestError, UnauthenticatedError } = require('../errors/index')
const bcrypt = require('bcryptjs')
require('dotenv').config()
const jwt = require('jsonwebtoken')

const register = async (req, res) => {
    // destructure request
    const { name, email, password } = req.body
    // hash password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)
    const tempUser = {
        name,
        email,
        password: hashedPassword
    }
    // store user
    const user = await User.create({ ...tempUser })
    // create jwt token
    const token = jwt.sign({ userId: user._id, name: user.name }, process.env.JWT_SECRET_TOKEN, {
        expiresIn: process.env.JWT_EXPIRES
    })
    // pass on the response
    res.status(StatusCodes.CREATED).json({ user: { name: user.name }, token })
}

const login = async (req, res) => {
    // destructure request
    const { email, password } = req.body
    // Validation for inputs
    if (!email || !password) {
        throw new BadRequestError('Please provide email and password')
    }
    // Searching for user in database
    const user = await User.findOne({ email })
    if (!user) {
        throw new UnauthenticatedError('Please provide correct credentials')
    }
    // comparing passwords
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
        throw new UnauthenticatedError('Please provide correct credentials')
    }
    // Generating access token
    const token = jwt.sign({ userId: user._id, name: user.name }, process.env.JWT_SECRET_TOKEN, {
        expiresIn: process.env.JWT_EXPIRES
    })
    // returning response
    res.status(StatusCodes.OK).json({ user: { name: user.name }, token })
}

module.exports = {
    register, login
}