package main

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
)

type handler struct{}

func (h *handler) login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	//Проверка, есть ли в базе данных пользователь или нет
	if username == "jon" && password == "password" {
		tokens, err := generateTokenPair()
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, tokens)
	}

	return echo.ErrUnauthorized
}

// Это API для refresh токенов
func (h *handler) token(c echo.Context) error {
	type tokenReqBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	tokenReq := tokenReqBody{}
	c.Bind(&tokenReq)

	// Parse берет строку токена и функцию для поиска ключа.
	// Последнее особенно полезно, если вы используете несколько ключей для своего приложения.
	// Стандарт заключается в использовании слова kid в заголовке токена для идентификации
	// какой существует ключ использователя, но предоставляется проанализированный токен (заголовок и утверждения)
	token, err := jwt.Parse(tokenReq.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		// Не забудьте проверить на валидность, alg - то, что вы ожидаете:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret это []byte содержащий ваш "секрет", например []byte("my_secret_key")
		return []byte("secret"), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Получаем запись пользователя из базы данных или
		// проходим по базе, чтобы проверить, может ли пользователь войти в систему
		if int(claims["sub"].(float64)) == 1 {

			newTokenPair, err := generateTokenPair()
			if err != nil {
				return err
			}

			return c.JSON(http.StatusOK, newTokenPair)
		}

		return echo.ErrUnauthorized
	}

	return err
}

func (h *handler) private(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	return c.String(http.StatusOK, "Welcome "+name+"!")
}
