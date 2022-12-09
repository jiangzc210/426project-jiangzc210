const express = require('express'); // Using the express framework
const app = express(); 
require("dotenv").config(); // Get environment variables from .env file(s)
var sqlite3 = require('sqlite3').verbose()
const cors = require('cors'); 
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');

const DBSOURCE = "usersdb.sqlite";
const auth = require("./middleware.js");

const port = 3004;
// initialize database
let db = new sqlite3.Database(DBSOURCE, (err) => {
    if (err) {
      // Cannot open database
      console.error(err.message)
      throw err
    } 
    else {        
        db.exec(`DROP TABLE IF EXISTS Users`);
        
        db.run(`CREATE TABLE Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username text, 
            Email text, 
            Password text,             
            Salt text,    
            Token text
            )`);  
    }
});

module.exports = db 

app.use(
    express.urlencoded(),
    cors({
        origin: 'http://localhost:3000'
    })
);

//Create new user
app.post("/app/user/new", async (req, res) => {
    var errors=[]
    try {
        const { Username, Email, Password } = req.body;

        if (!Username){
            errors.push("Username is missing");
        }
        if (!Email){
            errors.push("Email is missing");
        }
        if (!Password){
            errors.push("Password is missing");
        }
        if (errors.length){
            res.status(400).json({"error":errors.join(",")});
            return;
        }
        let userExists = false;
        
        
        var sql = "SELECT * FROM Users WHERE Username = ?"        
        await db.all(sql, Username, (err, result) => {
            if (err) {
                res.status(402).json({"error":err.message});
                return;
            }
            
            if(result.length === 0) {                
                
                var salt = bcrypt.genSaltSync(10);

                var data = {
                    Username: Username,
                    Email: Email,
                    Password: bcrypt.hashSync(Password, salt),
                    Salt: salt,
                    DateCreated: Date('now')
                }
        
                var sql ='INSERT INTO Users (Username, Email, Password, Salt, DateCreated) VALUES (?,?,?,?,?)'
                var params =[data.Username, data.Email, data.Password, data.Salt, Date('now')]
                var user = db.run(sql, params, function (err, innerResult) {
                    if (err){
                        res.status(400).json({"error": err.message})
                        return;
                    }
                  
                }); 
                res.status(200).send("New User Created");
            }            
            else {
                userExists = true;
                res.status(404).send("User Already Exist. Please Login");  
            }
        });
  /*
        setTimeout(() => {
            if(!userExists) {
                res.status(201).json("Success");    
            } else {
                res.status(201).json("Record already exists. Please login");    
            }            
        }, 500);
    } catch (err) {
      console.log(err);
    }*/
})


//handle user login
app.post("/app/user/login", async (req, res) => {  
  try {      
    const { Username, Password } = req.body;
        // Make sure there is an Email and Password in the request
        if (!(Username && Password)) {
            res.status(400).send("All input is required");
        }
            
        let user = [];
        
        var stmt = "SELECT * FROM Users WHERE Username = ?";
        db.all(stmt, Username, function(err, rows) {
            if (err){
                res.status(400).json({"error": err.message})
                return;
            }

            rows.forEach(function (row) {
                user.push(row);                
            })
            
            var PHash = bcrypt.hashSync(Password, user[0].Salt);
       
            if(PHash === user[0].Password) {
                // * CREATE JWT TOKEN
                const token = jwt.sign(
                    { user_id: user[0].Id, username: user[0].Username},
                      process.env.TOKEN_KEY,
                    {
                      expiresIn: "1h", // 60s = 60 seconds - (60m = 60 minutes, 2h = 2 hours, 2d = 2 days)
                    }  
                );

                user[0].Token = token;

            } else {
                return res.status(400).send("Incorrect credentials");          
            }

           return res.status(200).json({"message":"You are logged in."});                
        });	
    
    } catch (err) {
      console.log(err);
    }    
});

//retrieve user information
app.get("/app/user/info/:username", (req, res, next) => {
    var stmt = "SELECT * FROM Users WHERE Username = ?"
    db.all(stmt, req.params.username, (err, rows) => {
        if (err) {
          res.status(400).json({"error":err.message});
          return;
        }
        res.json({
            "message":"success",
            "Username":rows[0].Username,
            "Email":rows[0].Email,
        })
      });
});

//update user information
app.post("/app/user/update:username", async (req, res) => {  
  try {      
    const { OldPassword, Email, Password } = req.body;
        // Make sure there is an Email and Password in the request
        if (!(OldPassword && Email && Password)) {
            res.status(400).send("All input is required");
        }
            
        let user = [];
        // authenticate user
        var stmt = "SELECT * FROM Users WHERE Username = ?";
        db.all(stmt, req.params.username, function(err, rows) {
            if (err){
                res.status(400).json({"error": err.message})
                return;
            }
            rows.forEach(function (row) {
                user.push(row);                
            })
            
            var PHash = bcrypt.hashSync(OldPassword, user[0].Salt);
       
            if(PHash === user[0].Password) {
                //update entry in db
                stmt = "UPDATE Users SET Email = ?, Password = ? WHERE Username = ?";
                db.run(stmt, [Email, bcrypt.hashSync(Password, user[0].Salt)], req.params.username);
            } else {
                return res.status(400).send("Incorrect credentials");          
            }

           return res.status(200).json({"message":"User info updated"});                
        });	
    
    } catch (err) {
      console.log(err);
    }    
});

//delete user information
app.post("/app/user/delete:username", async (req, res) => {  
  try {      
    const { Password } = req.body;
        // Make sure there is an Email and Password in the request
        if (!Password) {
            res.status(400).send("Password is required");
        }
            
        let user = [];
        // authenticate user
        var stmt = "SELECT * FROM Users WHERE Username = ?";
        db.all(stmt, req.params.username, function(err, rows) {
            if (err){
                res.status(400).json({"error": err.message})
                return;
            }
            rows.forEach(function (row) {
                user.push(row);                
            })
            
            var PHash = bcrypt.hashSync(Password, user[0].Salt);
       
            if(PHash === user[0].Password) {
                //delete entry in db
                stmt = "DELETE FORM TABLE WHERE Username = ?";
                db.run(stmt, req.params.username);
            } else {
                return res.status(400).send("Incorrect credentials");          
            }

           return res.status(200).json({"message":"User account deleted"});                
        });	
    
    } catch (err) {
      console.log(err);
    }    
});

//retrieve login status
app.get("/app/user/login", auth, (req, res) => {
    res.status(200).json({"message":"You are logged in."});
});

app.listen(port, () => console.log(`API listening on port ${port}!`));


