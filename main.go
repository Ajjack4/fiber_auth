package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

var (
	secretKey = "supersecretkey"
    db *sql.DB
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	ID       int   `json:"id"` 
	Username string 
	Password string 
	
}

var mockUser = User{
	ID:       1,
	Username: "testuser",
	Password: "password123",
}
func initDB()error{
	var err error
	dsn:="root:Ajin4594@tcp(127.0.0.1:3306)/auth"
	
	db, err = sql.Open("mysql", dsn)
	if err!= nil {
        return fmt.Errorf("failed to connect to db: %v", err)
    }
	fmt.Println("inside db")
	return db.Ping()
}

func main() {

	if err:=initDB();err!=nil {
		panic(err)
	}
	defer db.Close()
	
	
	
	app := fiber.New()
    
	app.Post("/login", loginHandler)
	app.Post("/Signup",SignupHandler)
	app.Get("/protected", authenticateJWT, protectedHandler)
	app.Put("/update", authenticateJWT, updateHandler)
    app.Delete("/delete",authenticateJWT, deleteHandler)

	app.Listen(":3000")
}


func SignupHandler(c *fiber.Ctx)error{
	var req User
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request format",
        })
    }
	if  req.Username == "" || req.Password == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "ID, username, and password are required",
        })
    }
	query := "INSERT INTO users (id, username, password) VALUES (?, ?, ?)"
	
	result, err := db.Exec(query, req.ID, req.Username, req.Password)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to save user to the database",
            "details": err.Error(),
        })
    }
    insertID,err:=result.LastInsertId()
	if err!= nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to get last insert ID",
            "details": err.Error(),
        })
	}
    // return c.Status(fiber.StatusCreated).JSON(fiber.Map{
    //     "message": "User signed up successfully",
    // })
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": insertID,
		"exp":     time.Now().Add(time.Minute * 30).Unix(),
	})
	   signedToken, err := token.SignedString([]byte(secretKey))
	   if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Could not generate token",
		})
	}

	return c.JSON(fiber.Map{
		"token": signedToken,
	})


	// var user User
	// if err:=c.BodyParser(&user);err!=nil{
	// 	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
    //         "error": "Invalid request",
    //     })
	// }
	// err:= db.QueryRow("SELECT id,username,password FROM users WHERE username=?",user.Username)
    // if err== nil {
	// 	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error":"User Already Exists"})
	// }
	// return nil
}

func loginHandler(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

    // var user User
	// err:= db.QueryRow("SELECT id,username,password FROM users WHERE username=?",req.username)
	var user User
	err:= db.QueryRow("SELECT id,username,password FROM users WHERE username=?",req.Username).Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid credentials",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	if req.Password!= user.Password {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Invalid credentials",
        })
    }
	// if req.Username != mockUser.Username || req.Password != mockUser.Password {
	// 	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
	// 		"error": "Invalid credentials",
	// 	})
	// }
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Minute * 30).Unix(),
	})
	   signedToken, err := token.SignedString([]byte(secretKey))
	   if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Could not generate token",
		})
	}

	return c.JSON(fiber.Map{
		"token": signedToken,
	})
}

func authenticateJWT(c *fiber.Ctx) error {
	
	
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Missing or invalid token",
		})
}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		    }
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
}

	c.Locals("user", token.Claims.(jwt.MapClaims))
	return c.Next()
  }

 func protectedHandler(c *fiber.Ctx) error {
	user := c.Locals("user").(jwt.MapClaims)
	  return c.JSON(fiber.Map{
		"message": "Welcome to the protected route!",
		"user":    user,
	})
}

func updateHandler(c *fiber.Ctx) error {
	claims := c.Locals("user").(jwt.MapClaims)
    userID := claims["user_id"].(float64)
	var req User
	if err := c.BodyParser(&req); err!= nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request",
        })
    }
	if req.Username == "" && req.Password == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "At least one field (username or password) must be provided",
        })
    }
	query := "UPDATE users SET username=?, password=? WHERE id=?"
	_, err := db.Exec(query, req.Username, req.Password, userID)
	if err!= nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to update user in the database",
            "details": err.Error(),
        })
	}
	return c.JSON(fiber.Map{
        "message": "User updated successfully",
		"user_id": userID,
		"claims": claims,
    })
}

func deleteHandler(c *fiber.Ctx) error {
	claims := c.Locals("user").(jwt.MapClaims)
    userID := claims["user_id"].(float64)
    query := "DELETE FROM users WHERE id=?"
    _, err := db.Exec(query, userID)
    if err!= nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to delete user from the database",
            "details": err.Error(),
        })
    }
    return c.JSON(fiber.Map{
        "message": "User deleted successfully",
    })
}