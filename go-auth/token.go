package main

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

func generateTokenPair() (map[string]string, error) {
	// Создаем токен
	token := jwt.New(jwt.SigningMethodHS256)

	// Устанавливаем права
	// Это информация, которую может использовать веб-интерфейс
	// Бэкэнд также может декодировать токен и получить администратора и т.д.
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = 1
	claims["name"] = "Jon Doe"
	claims["admin"] = true
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	// Генерируем закодирванный токен и посылаем в качестве ответа
	// Строка подписи должна быть секретной (сгенерированный UUID тоже работает)
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return nil, err
	}

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["sub"] = 1
	rtClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	rt, err := refreshToken.SignedString([]byte("secret"))
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"access_token":  t,
		"refresh_token": rt,
	}, nil
}
