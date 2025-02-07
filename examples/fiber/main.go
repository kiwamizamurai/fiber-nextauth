package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v5"
	nextauthjwt "github.com/kiwamizamurai/fiber-nextauth/pkg"
)

func main() {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.Printf("Error occurred: %v", err)
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3001,http://localhost:3002",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH",
		ExposeHeaders:    "Set-Cookie",
	}))

	app.Use(func(c *fiber.Ctx) error {
		log.Printf("Request: %s %s", c.Method(), c.Path())
		log.Printf("Headers: %v", c.GetReqHeaders())
		log.Printf("Cookie Header: %v", c.GetReqHeaders()["Cookie"])
		log.Printf("Session Cookie v4: %v", c.Cookies("next-auth.session-token"))
		log.Printf("Session Cookie v5: %v", c.Cookies("authjs.session-token"))
		return c.Next()
	})

	// v4 routes
	v4 := app.Group("/v4")
	v4.Use(nextauthjwt.New(nextauthjwt.NewV4Config()).Middleware())
	v4.Get("/test", handleTest)

	// v5 routes
	v5 := app.Group("/v5")
	v5.Use(nextauthjwt.New(nextauthjwt.DefaultConfig()).Middleware())
	v5.Get("/test", handleTest)

	log.Fatal(app.Listen(":3000"))
}

func handleTest(c *fiber.Ctx) error {
	claims, ok := c.Locals("user").(jwt.MapClaims)
	if !ok {
		log.Printf("Failed to get user claims from context: %v", c.Locals("user"))
		return c.Status(fiber.StatusInternalServerError).JSON(APIResponse{
			Error: "Failed to get user claims",
		})
	}

	userClaims := UserClaims{
		Name:  claims["name"].(string),
		Email: claims["email"].(string),
		Sub:   claims["sub"].(string),
	}

	response := APIResponse{
		Message: "Returned user claims from backend",
		User: User{
			Name:  userClaims.Name,
			Email: userClaims.Email,
		},
	}
	log.Printf("Sending response: %+v", response)
	return c.JSON(response)
}
