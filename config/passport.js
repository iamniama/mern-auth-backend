require('dotenv').config();
// A passport strategy for authenticating with a JSON Web Token
// This allows to authenticate endpoints using a token
const {Strategy, ExtractJwt} = require('passport-jwt')
const mongoose = require('mongoose')
//import user model
const {User} = require('../models/user')


const options = {};

options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken()
options.secretOrKey = process.env.JWT_SECRET

module.exports = (passport) => {
    passport.use(new Strategy(options, (jwt_payload, done)=>{
        //find user by _id
        //is user in DB?
        User.findById(jwt_payload.id)
            .then(user =>{
                //done is a callback that is returned to indicate user or false
                if(user) {
                    return done(null, user)
                }else{
                    //no user
                    return done(null, false)
                }
            })
            .catch(error =>{
                console.log("******Error during passport.js: ********")
                console.log(error)
            })
    }))
}