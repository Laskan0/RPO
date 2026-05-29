package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"lab2/internal/model"
	"lab2/internal/repository"
)

const tokenLifetime = 24 * time.Hour

var ErrInvalidCredentials = errors.New("invalid credentials")

type Service struct {
	store     *repository.Store
	jwtSecret []byte
}

type Claims struct {
	UserID   int64  `json:"user_id"`
	Login    string `json:"login"`
	IsAdmin  bool   `json:"is_admin"`
	FullName string `json:"full_name"`
	jwt.RegisteredClaims
}

func NewService(store *repository.Store, jwtSecret string) *Service {
	return &Service{
		store:     store,
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *Service) Login(ctx context.Context, login string, password string) (string, *model.User, error) {
	user, err := s.store.GetUserByLogin(ctx, login)
	if err != nil {
		return "", nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", nil, ErrInvalidCredentials
	}

	token, err := s.createToken(user)
	if err != nil {
		return "", nil, fmt.Errorf("create jwt token: %w", err)
	}

	return token, user, nil
}

func (s *Service) ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func (s *Service) createToken(user *model.User) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   user.ID,
		Login:    user.Login,
		IsAdmin:  user.IsAdmin,
		FullName: user.FullName,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", user.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenLifetime)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}
