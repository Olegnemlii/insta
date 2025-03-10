package config

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	MailopostAPIKey     string
	MailopostSender     string
	RedisAddr           string
	RedisPassword       string
	RedisDB             int
	JwtSecret           string
	VerificationCodeTTL int
	AccessTokenTTL      int
	RefreshTokenTTL     int
	DatabaseURL         string
}

var Cfg Config

func LoadConfig() (Config, error) {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file:", err)
	}

	mailopostAPIKey := os.Getenv("MAILOPOST_API_KEY")
	mailopostSender := os.Getenv("MAILOPOST_SENDER")
	redisAddr := os.Getenv("REDIS_ADDR")
	redisPassword := os.Getenv("REDIS_PASSWORD")
	redisDBStr := os.Getenv("REDIS_DB")
	jwtSecret := os.Getenv("JWT_SECRET")
	verificationCodeTTLStr := os.Getenv("VERIFICATION_CODE_TTL")
	accessTokenTTLStr := os.Getenv("ACCESS_TOKEN_TTL")
	refreshTokenTTLStr := os.Getenv("REFRESH_TOKEN_TTL")
	databaseURL := os.Getenv("DATABASE_URL")

	if mailopostAPIKey == "" || mailopostSender == "" || redisAddr == "" || jwtSecret == "" || verificationCodeTTLStr == "" || accessTokenTTLStr == "" || refreshTokenTTLStr == "" || databaseURL == "" {
		return Config{}, fmt.Errorf("missing required environment variables")
	}

	redisDB, err := strconv.Atoi(redisDBStr)
	if err != nil {
		redisDB = 0
	}

	verificationCodeTTL, err := strconv.Atoi(verificationCodeTTLStr)
	if err != nil {
		verificationCodeTTL = 300
	}

	accessTokenTTL, err := strconv.Atoi(accessTokenTTLStr)
	if err != nil {
		accessTokenTTL = 3600
	}

	refreshTokenTTL, err := strconv.Atoi(refreshTokenTTLStr)
	if err != nil {
		refreshTokenTTL = 604800
	}

	return Config{
		MailopostAPIKey:     mailopostAPIKey,
		MailopostSender:     mailopostSender,
		RedisAddr:           redisAddr,
		RedisPassword:       redisPassword,
		RedisDB:             redisDB,
		JwtSecret:           jwtSecret,
		VerificationCodeTTL: verificationCodeTTL,
		AccessTokenTTL:      accessTokenTTL,
		RefreshTokenTTL:     refreshTokenTTL,
		DatabaseURL:         databaseURL,
	}, nil
}
