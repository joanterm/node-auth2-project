const router = require("express").Router();
const Users = require("./users-model.js");
const { restricted, only } = require("../auth/auth-middleware.js");


//GET -> in Postman, go to Headers -> add "Authorization" and "Value" (token from login)
router.get("/", restricted, (req, res, next) => { // done for you
  console.log(req.headers)
  Users.find()
    .then(users => {     
      res.json(users);
    })
    .catch(next);
});

//GET -> only admins should have access to all users
router.get("/:user_id", restricted, only('admin'), (req, res, next) => { // done for you
  Users.findById(req.params.user_id)
    .then(user => {
      res.json(user);
    })
    .catch(next);
});

module.exports = router;


/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    }
  ]
 */

  /**
  [GET] /api/users/:user_id

  This endpoint is RESTRICTED: only authenticated users with role 'admin'
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    }
  ]
 */