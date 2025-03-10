package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authpb "insta/auth/pkg/pb"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("не удалось подключиться: %v", err)
	}
	defer conn.Close()
	c := authpb.NewAuthClient(conn)

	email := os.Getenv("TEST_EMAIL")
	password := os.Getenv("TEST_PASSWORD")
	if email == "" || password == "" {
		log.Fatal("TEST_EMAIL или TEST_PASSWORD не установлены в переменных окружения")
	}

	registerCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registerResponse, err := c.Register(registerCtx, &authpb.RegisterRequest{Email: email, Password: password})
	if err != nil {
		log.Fatalf("ошибка регистрации: %v", err)
	}
	log.Printf("регистрация успешна, подпись: %s", registerResponse.GetSignature())
	signature := registerResponse.GetSignature()

	var verificationCode string
	fmt.Print("введите код подтверждения: ")
	_, err = fmt.Scanln(&verificationCode)
	if err != nil {
		log.Fatalf("ошибка при вводе кода: %v", err)
	}

	verifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	verifyResponse, err := c.VerifyCode(verifyCtx, &authpb.VerifyCodeRequest{Code: verificationCode, Signature: signature})
	if err != nil {
		log.Fatalf("ошибка подтверждения: %v", err)
	}
	log.Printf("код подтвержден. Access Token: %s", verifyResponse.GetAccessToken().GetData())

	loginCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	loginResponse, err := c.Login(loginCtx, &authpb.LoginRequest{Email: email, Password: password})
	if err != nil {
		log.Fatalf("ошибка входа: %v", err)
	}
	log.Printf("вход успешен. Access Token: %s", loginResponse.GetAccessToken().GetData())

	refreshCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	refreshResponse, err := c.RefreshTokens(refreshCtx, &authpb.RefreshTokensRequest{
		AccessToken:  loginResponse.GetAccessToken(),
		RefreshToken: loginResponse.GetRefreshToken(),
	})
	if err != nil {
		log.Fatalf("ошибка обновления токенов: %v", err)
	}
	log.Printf("токены обновлены. новый Access Token: %s", refreshResponse.GetAccessToken().GetData())

	getMeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	getMeResponse, err := c.GetMe(getMeCtx, &authpb.GetMeRequest{AccessToken: refreshResponse.GetAccessToken()})
	if err != nil {
		log.Fatalf("ошибка получения информации о пользователе: %v", err)
	}
	log.Printf("данные пользователя: ID: %s, Email: %s", getMeResponse.GetUser().GetId(), getMeResponse.GetUser().GetEmail())

	logOutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	logOutResponse, err := c.LogOut(logOutCtx, &authpb.LogOutRequest{AccessToken: refreshResponse.GetAccessToken()})
	if err != nil {
		log.Fatalf("ошибка выхода: %v", err)
	}
	log.Printf("выход выполнен: %v", logOutResponse.GetSuccess())
}
