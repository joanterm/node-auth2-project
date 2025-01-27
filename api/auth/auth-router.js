const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken")
const Users = require("../users/users-model")
const bcrypt = require("bcryptjs")

//POST -> BCRYPT -> REGISTER
router.post("/register", validateRoleName, (req, res, next) => {
  const {username, password, role_name} = req.body
  const hash = bcrypt.hashSync(password, 12)
  const user = {username: username, password: hash, role_name}
  Users.add(user)
    .then((result) => {  
      res.status(201).json({user_id: result.user_id, username: username, role_name: result.role_name.trim()})
    })
    .catch((err) => {
      console.log(err);      
    })
});

//POST -> BCRYPT -> GENERATE TOKEN INSTEAD OF SESSION -> LOGIN
router.post("/login", checkUsernameExists, (req, res, next) => {
  const {username, password} = req.body
  Users.findBy({"username": username}).first()
    .then((result) => {
      if(bcrypt.compareSync(password, result.password)) {
        const token = generateToken(result)
        res.status(200).json({message: `${username} is back!`, token})
      } else {
        res.status(401).json({message: "Invalid Credentials"})
      }
    })
});

//GENERATE JWT TOKEN
function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  };
  const options = {
    expiresIn: "1d"
  };
  return jwt.sign(payload, JWT_SECRET, options)
}

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }
    The token must expire in one day, and must provide the following information
    in its payload:
    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */


      /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */


module.exports = router;
