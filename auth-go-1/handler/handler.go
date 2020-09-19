package handlers

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"jwt-app/auth"
	"net/http"
	"os"
)

// ProfileHandler struct
type profileHandler struct {
	rd      auth.AuthInterface
	tk      auth.TokenInterface
}

func NewProfile(rd auth.AuthInterface, tk auth.TokenInterface) *profileHandler {
	return &profileHandler{rd, tk}
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}
//User
var user = User {
	ID:           "1",
	Username: "username",
	Password: "password",
}

type Todo struct {
	UserID string `json:"user_id"`
	Title string `json:"title"`
	Body string `json:"body"`
}

func (h *profileHandler) Login(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}
	//сравнивание пользователя из запроса с тем, что мы создали:
	if user.Username != u.Username || user.Password != u.Password {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}
	ts, err := h.tk.CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	saveErr := h.rd.CreateAuth(user.ID, ts)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

func (h *profileHandler) Logout(c *gin.Context) {
	//Если метаданные переданы и токены действительны, удаление их из хранилища Redis
	metadata, _ := h.tk.ExtractTokenMetadata(c.Request)
	if metadata != nil {
		deleteErr := h.rd.DeleteTokens(metadata)
		if deleteErr != nil {
			c.JSON(http.StatusBadRequest, deleteErr.Error())
			return
		}
	}
	c.JSON(http.StatusOK, "Successfully logged out")
}

func (h *profileHandler) CreateTodo(c *gin.Context) {
	var td Todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	metadata, err := h.tk.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userId, err := h.rd.FetchAuth(metadata.TokenUuid)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = userId

	//тут можно создать базу данных

	c.JSON(http.StatusCreated, td)
}


func (h *profileHandler) Refresh(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	refreshToken := mapToken["refresh_token"]

	//верификация токена
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	//если есть ошибка, токен просрочен
	if err != nil {
		c.JSON(http.StatusUnauthorized, "Refresh token expired")
		return
	}
	//Валидный ли токен?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, err)
		return
	}
	//Пока токен валидный, забираем uuid
	claims, ok := token.Claims.(jwt.MapClaims) //Токен должен соответствовать MapClaims
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string) //преобразование интерфейса в строку
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, err)
			return
		}
		userId, roleOk := claims["user_id"].(string)
		if  roleOk == false {
			c.JSON(http.StatusUnprocessableEntity, "unauthorized")
			return
		}
		//Удаление предшествующего refresh токена
		delErr := h.rd.DeleteRefresh(refreshUuid)
		if delErr != nil { //if any goes wrong
			c.JSON(http.StatusUnauthorized, "unauthorized")
			return
		}
		//Создание новой пары refresh - access токенов
		ts, createErr := h.tk.CreateToken(userId)
		if  createErr != nil {
			c.JSON(http.StatusForbidden, createErr.Error())
			return
		}
		//сохранение метаданных токенов в redis
		saveErr := h.rd.CreateAuth(userId, ts)
		if saveErr != nil {
			c.JSON(http.StatusForbidden, saveErr.Error())
			return
		}
		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}
		c.JSON(http.StatusCreated, tokens)
	} else {
		c.JSON(http.StatusUnauthorized, "refresh expired")
	}
}













