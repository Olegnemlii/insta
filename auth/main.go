package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"insta/auth/config"
	"insta/auth/database"
	authpb "insta/auth/pkg/pb"

	"github.com/google/uuid"
)

type server struct {
	authpb.UnimplementedAuthServer
	redisClient *redis.Client
	jwtSecret   []byte
	db          *database.Database
}

func (s *server) Register(ctx context.Context, req *authpb.RegisterRequest) (*authpb.RegisterResponse, error) {
	email := req.GetEmail()
	password := req.GetPassword()

	if email == "" || password == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email and password are required")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("error hashing password: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to hash password")
	}

	signature, err := generateSignature()
	if err != nil {
		log.Printf("error generate Signature: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to generate Signature")
	}

	user, err := s.db.CreateUser(ctx, email, string(hashedPassword))
	if err != nil {
		log.Printf("error creating user in database: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to create user")
	}

	err = s.db.UpdateUserSignature(ctx, user.ID, signature)
	if err != nil {
		log.Printf("error updating user signature in database: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to update user signature")
	}

	err = s.sendVerificationCode(ctx, email, signature)
	if err != nil {
		log.Printf("error sending verification code: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to send verification code")
	}

	return &authpb.RegisterResponse{Signature: signature}, nil
}

func (s *server) sendVerificationCode(ctx context.Context, email, signature string) error {
	if signature == "" {
		log.Println("Error: signature is empty")
		return fmt.Errorf("signature cannot be empty")
	}

	code := uuid.New().String()

	err := s.db.StoreVerificationCode(ctx, email, code, signature)
	if err != nil {
		log.Printf("error storing verification code: %v", err)
		return err
	}

	err = s.sendVerificationEmail(ctx, email, code)
	if err != nil {
		log.Printf("error sending verification email: %v", err)
		return err
	}

	return nil
}

func (s *server) VerifyCode(ctx context.Context, req *authpb.VerifyCodeRequest) (*authpb.VerifyCodeResponse, error) {
	log.Println("VerifyCode вызван")

	code := req.GetCode()
	signature := req.GetSignature()
	log.Printf("получен код: %s", code)
	log.Printf("получена подпись: %s", signature)

	if code == "" || signature == "" {
		log.Println("ошибка: код или подпись пустые")
		return nil, status.Errorf(codes.InvalidArgument, "code and signature are required")
	}

	email, err := s.db.GetEmailBySignature(ctx, signature)
	if err != nil {
		log.Printf("ошибка при получении email по signature: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to get email by signature")
	}

	storedCode, err := s.db.GetVerificationCode(ctx, email)
	if err != nil {
		log.Printf("ошибка при получении verification code из БД: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid verification code")
	}

	log.Printf("Код в базе: %s", storedCode)

	if code != storedCode {
		log.Println("ошибка: введенный код не совпадает с кодом в БД")
		return nil, status.Errorf(codes.InvalidArgument, "invalid verification code")
	}

	err = s.db.DeleteVerificationCode(ctx, email)
	if err != nil {
		log.Printf("error deleting verification code from database: %v", err)
	}

	user, err := s.db.GetUserByEmail(ctx, email)
	if err != nil {
		log.Printf("error getting user from database: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to get user")
	}

	accessToken, err := s.generateJWT(user.Email, int(config.Cfg.AccessTokenTTL))
	if err != nil {
		log.Printf("ошибка при генерации access token: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to generate access token")
	}
	log.Println("аccess token сгенерирован:", accessToken)

	refreshToken, err := s.generateJWT(user.Email, int(config.Cfg.RefreshTokenTTL))
	if err != nil {
		log.Printf("ошибка при генерации refresh token: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to generate refresh token")
	}
	log.Println("refresh token сгенерирован:", refreshToken)

	log.Println("сохранение refresh token в БД...")
	err = s.db.StoreRefreshToken(ctx, user.Email, accessToken, refreshToken)

	if err != nil {
		log.Printf("ошибка при сохранении refresh token в БД: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to store refresh token")
	}
	log.Println("refresh token успешно сохранен в БД!")

	pbUser := &authpb.User{
		Id:    user.ID.String(),
		Email: user.Email,
	}

	accessTokenStruct := &authpb.Token{
		Data:      accessToken,
		ExpiresAt: time.Now().Add(time.Duration(config.Cfg.AccessTokenTTL) * time.Second).Unix(),
	}

	refreshTokenStruct := &authpb.Token{
		Data:      refreshToken,
		ExpiresAt: time.Now().Add(time.Duration(config.Cfg.RefreshTokenTTL) * time.Second).Unix(),
	}

	return &authpb.VerifyCodeResponse{
		AccessToken:  accessTokenStruct,
		RefreshToken: refreshTokenStruct,
		User:         pbUser,
	}, nil
}

func (s *server) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	email := req.GetEmail()
	password := req.GetPassword()

	if email == "" || password == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email and password are required")
	}

	user, err := s.db.GetUserByEmail(ctx, email)
	if err != nil {
		log.Printf("error getting user from database: %v", err)
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		log.Printf("invalid password: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	accessToken, err := s.generateJWT(user.Email, int(config.Cfg.AccessTokenTTL))
	if err != nil {
		log.Printf("error generating access token: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to generate access token")
	}
	refreshToken, err := s.generateJWT(user.Email, int(config.Cfg.RefreshTokenTTL))
	if err != nil {
		log.Printf("error generating refresh token: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to generate refresh token")
	}

	err = s.db.StoreRefreshToken(ctx, user.Email, accessToken, refreshToken)

	if err != nil {
		log.Printf("error storing refresh token in database: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to store refresh token")
	}

	pbUser := &authpb.User{
		Id:    user.ID.String(),
		Email: user.Email,
	}

	accessTokenStruct := &authpb.Token{
		Data:      accessToken,
		ExpiresAt: time.Now().Add(time.Duration(config.Cfg.AccessTokenTTL) * time.Second).Unix(),
	}

	refreshTokenStruct := &authpb.Token{
		Data:      refreshToken,
		ExpiresAt: time.Now().Add(time.Duration(config.Cfg.RefreshTokenTTL) * time.Second).Unix(),
	}

	return &authpb.LoginResponse{
		AccessToken:  accessTokenStruct,
		RefreshToken: refreshTokenStruct,
		User:         pbUser,
	}, nil
}

func (s *server) RefreshTokens(ctx context.Context, req *authpb.RefreshTokensRequest) (*authpb.RefreshTokensResponse, error) {
	refreshToken := req.GetRefreshToken().GetData()
	accessToken := req.GetAccessToken().GetData()

	if refreshToken == "" || accessToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "refresh token and access token are required")
	}

	email, err := s.verifyJWT(accessToken)
	if err != nil {
		log.Printf("ошибка валидации access token: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	// Получаем сохраненный refresh token из БД
	storedRefreshToken, err := s.db.GetRefreshToken(ctx, email)
	if err != nil {
		log.Printf("ошибка получения refresh token из БД: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid refresh token")
	}

	// Проверяем, что переданный refresh token совпадает с тем, что в БД
	if refreshToken != storedRefreshToken {
		log.Println("ошибка: переданный refresh token не совпадает с хранимым в БД")
		return nil, status.Errorf(codes.InvalidArgument, "invalid refresh token")
	}

	// Получаем пользователя
	user, err := s.db.GetUserByEmail(ctx, email)
	if err != nil {
		log.Printf("ошибка получения пользователя: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to get user")
	}

	// Генерируем новые access и refresh токены
	newAccessToken, err := s.generateJWT(email, int(config.Cfg.AccessTokenTTL))
	if err != nil {
		log.Printf("ошибка генерации access token: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to generate access token")
	}

	newRefreshToken, err := s.generateJWT(email, int(config.Cfg.RefreshTokenTTL))
	if err != nil {
		log.Printf("ошибка генерации refresh token: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to generate refresh token")
	}

	// Удаляем старый refresh token перед сохранением нового
	log.Println("удаляем старый refresh token из БД...")
	err = s.db.DeleteRefreshToken(ctx, email)
	if err != nil {
		log.Printf("ошибка удаления старого refresh token: %v", err)
	}

	// Сохраняем новый refresh token
	log.Println("сохраняем новый refresh token в БД...")
	err = s.db.StoreRefreshToken(ctx, email, newAccessToken, newRefreshToken)
	if err != nil {
		log.Printf("ошибка сохранения нового refresh token: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to store refresh token")
	}

	// Подготавливаем ответ
	pbUser := &authpb.User{
		Id:    user.ID.String(),
		Email: user.Email,
	}

	accessTokenStruct := &authpb.Token{
		Data:      newAccessToken,
		ExpiresAt: time.Now().Add(time.Duration(config.Cfg.AccessTokenTTL) * time.Second).Unix(),
	}

	refreshTokenStruct := &authpb.Token{
		Data:      newRefreshToken,
		ExpiresAt: time.Now().Add(time.Duration(config.Cfg.RefreshTokenTTL) * time.Second).Unix(),
	}

	log.Println("access и refresh токены успешно обновлены!")

	return &authpb.RefreshTokensResponse{
		AccessToken:  accessTokenStruct,
		RefreshToken: refreshTokenStruct,
		User:         pbUser,
	}, nil
}

func (s *server) LogOut(ctx context.Context, req *authpb.LogOutRequest) (*authpb.LogOutResponse, error) {
	accessToken := req.GetAccessToken().GetData()

	email, err := s.verifyJWT(accessToken)
	if err != nil {
		log.Printf("invalid access token: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	err = s.db.DeleteRefreshToken(ctx, email)
	if err != nil {
		log.Printf("error deleting refresh token from database: %v", err)
	}

	return &authpb.LogOutResponse{Success: true}, nil
}

func (s *server) GetMe(ctx context.Context, req *authpb.GetMeRequest) (*authpb.GetMeResponse, error) {
	accessToken := req.GetAccessToken().GetData()

	email, err := s.verifyJWT(accessToken)
	if err != nil {
		log.Printf("invalid access token: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	user, err := s.db.GetUserByEmail(ctx, email)
	if err != nil {
		log.Printf("error getting user from database: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to get user")
	}

	pbUser := &authpb.User{
		Id:    user.ID.String(),
		Email: user.Email,
	}

	return &authpb.GetMeResponse{User: pbUser}, nil
}

func (s *server) sendVerificationEmail(ctx context.Context, email, code string) error {
	apiURL := "https://api.mailopost.ru/v1/email/messages"

	payload := map[string]interface{}{
		"api_key":    config.Cfg.MailopostAPIKey,
		"from_email": config.Cfg.MailopostSender,
		"to":         email,
		"subject":    "код подтверждения",
		"text":       fmt.Sprintf("ваш код подтверждения: %s", code),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ошибка при формировании JSON: %v", err)
		return err
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("ошибка при создании HTTP-запроса: %v", err)
		return err
	}

	req = req.WithContext(ctx)

	req.Header.Set("Authorization", "Bearer "+config.Cfg.MailopostAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ошибка при отправке HTTP-запроса: %v", err)
		return err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("ошибка отправки письма: %s, тело ответа: %s", resp.Status, string(body))
		return fmt.Errorf("ошибка отправки письма: %s", resp.Status)
	}

	log.Println("письмо успешно отправлено!")
	return nil
}

func (s *server) generateJWT(email string, ttl int) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Duration(ttl) * time.Second).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *server) verifyJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return s.jwtSecret, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email, ok := claims["email"].(string)
		if !ok {
			return "", fmt.Errorf("email not found in token claims")
		}
		return email, nil
	}

	return "", fmt.Errorf("invalid token")
}

func generateSignature() (string, error) {
	id := uuid.New()
	return id.String(), nil
}

func main() {

	var err error

	config.Cfg, err = config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.Cfg.RedisAddr,
		Password: config.Cfg.RedisPassword,
		DB:       config.Cfg.RedisDB,
	})

	ctx := context.Background()
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("failed to connect to Redis: %v", err)
	}

	db, err := database.NewDatabase(config.Cfg.DatabaseURL, time.Second*5)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	s := grpc.NewServer()
	authpb.RegisterAuthServer(s, &server{
		redisClient: redisClient,
		jwtSecret:   []byte(config.Cfg.JwtSecret),
		db:          db,
	})

	reflection.Register(s)

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
