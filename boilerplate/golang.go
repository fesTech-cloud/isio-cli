package boilerplate

import "fmt"

func StarterGenerator(packageName string) []func() string {
	return []func() string{
		func() string { return server(packageName) },
		func() string { return root(packageName) },
		func() string { return config(packageName) },
		func() string { return constant() },
		func() string { return handler(packageName) },
		func() string { return service(packageName) },
		func() string { return model(packageName) },
		func() string { return repository(packageName) },
		func() string { return routes(packageName) },
		func() string { return provider(packageName) },
		func() string { return interfacesx() },
		func() string { return middlewarex(packageName) },
		func() string { return healthx(packageName) },
		func() string { return appEnv() },
		func() string { return main(packageName) },
		func() string { return ignore() },
	}
}

func server(packageName string) string {
	text := fmt.Sprintf(`
package server

import (
	"%s/x/interfacesx"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type GinServer interface {
	Start(ctx context.Context, httpAddr string) error
	RegisterRoute(method, path string, handler gin.HandlerFunc)
	Shutdown(ctx context.Context) error
	RegisterMiddleware(path string, middleware ...gin.HandlerFunc)
	RegisterGroup(path string, routes []interfacesx.RouteDefinition, middlewares ...gin.HandlerFunc)
}

type GinServerBuilder struct{}

type ginServer struct {
	engine *gin.Engine
	server *http.Server
}

func NewGinServerBuilder() *GinServerBuilder {
	return &GinServerBuilder{}
}

func (gb *GinServerBuilder) Build() GinServer {
	engine := gin.Default()
	config := cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "token", "secret"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           24 * time.Hour,
	}

	engine.Use(cors.New(config))

	engine.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, interfacesx.ErrorResponse{
			Message: "Resource not found at all",
			Code:    http.StatusNotFound,
			Status:  false,
		})
	})
	return &ginServer{engine: engine}
}

func (gs *ginServer) RegisterRoute(method, path string, handler gin.HandlerFunc) {
	switch method {
	case "GET":
		gs.engine.GET(path, handler)
	case "POST":
		gs.engine.POST(path, handler)
	case "PUT":
		gs.engine.PUT(path, handler)
	case "DELETE":
		gs.engine.DELETE(path, handler)
	case "PATCH":
		gs.engine.PATCH(path, handler)
	default:
		logrus.Errorf("Unsupported HTTP method: ", method)
	}
}

func (gs *ginServer) Start(ctx context.Context, httpAddr string) error {
	gs.server = &http.Server{
		Addr:    httpAddr,
		Handler: gs.engine,
	}

	go func() {
		if err := gs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("HTTP server listen error", err)
		}
	}()

	logrus.Infof("HTTP server listening on", httpAddr)
	return nil
}

func (gs *ginServer) RegisterMiddleware(path string, middleware ...gin.HandlerFunc) {
	gs.engine.Group(path).Use(middleware...)
}

func (gs *ginServer) Shutdown(ctx context.Context) error {
	logrus.Infof("Shutting down server...")
	if err := gs.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed:", err)
	}
	logrus.Infof("Server gracefully stopped")
	return nil
}

func (gs *ginServer) RegisterGroup(path string, routes []interfacesx.RouteDefinition, middlewares ...gin.HandlerFunc) {
	group := gs.engine.Group(path)
	group.Use(middlewares...)
	for _, route := range routes {
		switch route.Method {
		case "GET":
			group.GET(route.Path, route.Handler)
		case "POST":
			group.POST(route.Path, route.Handler)
		case "PUT":
			group.PUT(route.Path, route.Handler)
		case "DELETE":
			group.DELETE(route.Path, route.Handler)
		case "PATCH":
			group.PATCH(route.Path, route.Handler)
		default:
			logrus.Errorf("Unsupported HTTP method:", route.Method)
		}
	}
}`, packageName)

	return text
}

func root(packageName string) string {
	text := fmt.Sprintf(`
package cmd

import (
	"%s/cmd/server"
	"%s/config"
	"%s/provider"
	"%s/x"
	"%s/x/healthx"
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Execute() {
	builder := server.NewGinServerBuilder()
	server := builder.Build()
	ctx := context.Background()

	db, er := config.DBSetup()

	if er != nil {
		logrus.Fatalf("Failed to setup database: ", er)
	}

	server.RegisterRoute("GET", "/v1/health", func(c *gin.Context) {
		healthx.CheckHealth(c, db)
	})

	provider.NewProvider(db, server)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.Start(ctx, os.Getenv(config.Port)); err != nil {
			logrus.Fatalf("Failed to start Gin server: ", err)
		}
	}()


	<-ctx.Done()
	logrus.Infof("Received shutdown signal")

	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logrus.Fatalf("Failed to gracefully shutdown Gin server: ", err)
	}
}

	`, packageName, packageName, packageName, packageName, packageName)

	return text
}

func config(packageName string) string {
	return fmt.Sprintf(`
package config

import (
	"%s/internal/model"
	"fmt"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func LoadEnv() {
	if err := godotenv.Load("app.env"); err != nil {
		logrus.Fatal("Error loading .env file")
	}

	InitSentry(os.Getenv(SentryDSN))
	defer Flush(5 * time.Second)
}

func DBSetup() (*gorm.DB, error) {
	LoadEnv()
	dns := os.Getenv(DataBaseURL)
	db, err := gorm.Open(postgres.Open(dns), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info)},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to open database connection", err)
	}

	if err := RunMigration(db); err != nil {
		return nil, fmt.Errorf("migration failed")
	}

	err = RunMigration(db)
	if err != nil {
		return nil, fmt.Errorf("error migrating DB", err)
	}
	return db, nil
}

func RunMigration(db *gorm.DB) error {
	logrus.Info("Running migrations")

	if err := db.AutoMigrate(
		&model.User{}); err != nil {
		logrus.Fatalf("Failed to migrate other models", err)
	}
	return nil
}

func InitSentry(dsn string) {
	err := sentry.Init(sentry.ClientOptions{
		Dsn: dsn,
	})
	if err != nil {
		logrus.Fatalf("sentry.Init", err)
	}
}

func Flush(timeout time.Duration) {
	sentry.Flush(timeout)
}`, packageName)
}

func constant() string {
	return fmt.Sprintf(`
	package config

    const (
	DataBaseURL   = "DATABASE_URL"
	SecretKey     = "SECRET_KEY"
	SentryDSN     = "SENTRY_DSN"
	Port        = "APP_PORT"
)`,
	)
}

func handler(packageName string) string {
	return fmt.Sprintf(`
package handler

import (
	"%s/internal/service"
	"%s/x"
	"%s/x/interfacesx"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type AuthHandler struct {
	userService service.AuthService
	validate    *validator.Validate
}

func NewAuthHandler(
	userService service.AuthService,

) *AuthHandler {
	return &AuthHandler{
		userService: userService,
		validate:    validator.New(),
	}
}

func (h *AuthHandler) CreateUserHandler(c *gin.Context) {
	var user interfacesx.CreateUserRequest
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusInternalServerError, interfacesx.ErrorResponse{
			Message: "Invalid request data sent",
			Code:    http.StatusInternalServerError,
			Status:  false,
		})

		return
	}
	if err := h.validate.Struct(user); err != nil {
		c.JSON(http.StatusBadRequest, interfacesx.ErrorResponse{
			Message: err.Error(),
			Code:    http.StatusBadRequest,
			Status:  false,
		})

		return
	}
	err := h.userService.CreateUserService(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, interfacesx.ErrorResponse{
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
			Status:  false,
		})

		return
	}

	c.JSON(http.StatusOK, interfacesx.SuccessResponse{
		Message: "user created successfully",
		Code:    http.StatusOK,
		Status:  true,
	})
}`, packageName, packageName, packageName)
}

func service(packageName string) string {
	return fmt.Sprintf(`
package service

import (
	"%s/internal/repository"
	"%s/x/interfacesx"
)

type AuthService interface {
	CreateUserService(userRequest interfacesx.CreateUserRequest) error
}

type authService struct {
	userRepo repository.AuthRepository
}

func NewAuthService(userRepo repository.AuthRepository) AuthService {
	return &authService{userRepo}
}

func (s *authService) CreateUserService(userRequest interfacesx.CreateUserRequest) error {
	_, err := s.userRepo.CreateUserRepo(userRequest)
	if err != nil {
		return err
	}
	return nil
}`, packageName, packageName)
}

func model(packageName string) string {
	return fmt.Sprintf(`
	package model

	import (
		"github.com/gofrs/uuid"
		"gorm.io/gorm"
	)

	// Define the User struct
	type User struct {
		gorm.Model
		ID        uuid.UUID ` + "`" + `gorm:"type:uuid;default:uuid_generate_v4()"` + "`" + `
		Email     string    ` + "`" + `gorm:"unique"` + "`" + `
		Surname   string    ` + "`" + `gorm:"default:''"` + "`" + `
		FirstName string    ` + "`" + `gorm:"default:''"` + "`" + `
		Password  string    ` + "`" + `gorm:"default:''"` + "`" + `
	}
	`)
}

func repository(packageName string) string {
	return fmt.Sprintf(`
package repository

import (
	"%s/internal/model"
	"%s/x/interfacesx"
	"fmt"

	"gorm.io/gorm"
)

type AuthRepository interface {
	CreateUserRepo(user interfacesx.CreateUserRequest) (*model.User, error)
}

type authRepository struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) AuthRepository {
	return &authRepository{db: db}
}

func (r *authRepository) CreateUserRepo(user interfacesx.CreateUserRequest) (*model.User, error) {
	var newUser *model.User

	// Create the new user
		newUser = &model.User{
			FirstName:     user.FirstName,
			Surname:       user.SurName,
			Email:         user.Email,
			Password:      user.Password,
		}
		if err := r.db.Create(newUser).Error; err != nil {
			return nil, fmt.Errorf("failed to create system user: ", err)
		}

	return newUser, nil
}`, packageName, packageName)
}

func routes(packageName string) string {
	return fmt.Sprintf(`
package routes

import (
	"%s/cmd/server"
	"%s/internal/handler"
	"%s/x/interfacesx"
	"%s/x/middlewarex"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func RegisterAuthRoutes(server server.GinServer, authHandler *handler.AuthHandler) {
	server.RegisterGroup("/v1/auth", []interfacesx.RouteDefinition{
		{Method: "POST", Path: "/create-user", Handler: authHandler.CreateUserHandler},
	}, func(c *gin.Context) {
		logrus.Infof("Request to %s", c.Request.URL.Path)
		middlewarex.CheckSecret(c)
	})
}`, packageName, packageName, packageName, packageName)
}

func provider(packageName string) string {
	return fmt.Sprintf(`
package provider

import (
	"%s/cmd/server"
	"%s/internal/handler"
	"%s/internal/repository"
	"%s/internal/routes"
	"%s/internal/service"

	"gorm.io/gorm"
)

func NewProvider(db *gorm.DB, server server.GinServer) {
	// Repositories Collection
	authRepo := repository.NewAuthRepository(db)

	// Services Collection
	authService := service.NewAuthService(authRepo)

	// Handlers Collection
	authHandler := handler.NewAuthHandler(authService)

	// Routes Registration
	routes.RegisterAuthRoutes(server, authHandler)
}`, packageName, packageName, packageName, packageName, packageName)
}

func interfacesx() string {
	return fmt.Sprintf(`
package interfacesx

import (
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
)

	// Define the ErrorResponse struct
	type ErrorResponse struct {
		Message string ` + "`" + `json:"message"` + "`" + `
		Code    int    ` + "`" + `json:"code"` + "`" + `
		Status  bool   ` + "`" + `json:"status"` + "`" + `
	}

	// Define the SuccessResponse struct
	type SuccessResponse struct {
		Message string ` + "`" + `json:"message"` + "`" + `
		Code    int    ` + "`" + `json:"code"` + "`" + `
		Status  bool   ` + "`" + `json:"status"` + "`" + `
	}

	// Define the RouteDefinition struct
	type RouteDefinition struct {
		Method  string
		Path    string
		Handler gin.HandlerFunc
	}

	// Define the CreateUserRequest struct
	type CreateUserRequest struct {
		FirstName string ` + "`" + `json:"firstName" validate:"required,min=2,max=100"` + "`" + `
		SurName   string ` + "`" + `json:"surName" validate:"required,min=2,max=100"` + "`" + `
		Password  string ` + "`" + `json:"password" validate:"required,min=6"` + "`" + `
		Email     string ` + "`" + `json:"email" validate:"email,required"` + "`" + `
	}

	// Define the UserResponse struct
	type UserResponse struct {
		ID        uuid.UUID ` + "`" + `json:"id"` + "`" + `
		Surname   string    ` + "`" + `json:"surname"` + "`" + `
		Firstname string    ` + "`" + `json:"firstname"` + "`" + `
		Email     string    ` + "`" + `json:"email"` + "`" + `
	}
	`)
}

func middlewarex(packageName string) string {
	return fmt.Sprintf(`
package middlewarex

import (
	"%s/config"
	"%s/x/interfacesx"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func CheckSecret(c *gin.Context) {
	key := c.GetHeader("secret")
	secretKey := os.Getenv(config.SecretKey)

	if key != secretKey {
		c.JSON(http.StatusUnauthorized, interfacesx.ErrorResponse{
			Message: "You are not authorized to this endpoint",
			Code:    http.StatusUnauthorized,
		})
		c.Abort()
		return
	}

	c.Next()
}`, packageName, packageName)
}

func healthx(packageName string) string {
	return fmt.Sprintf(`
package healthx

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func CheckHealth(c *gin.Context, db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, HealthCheckResponse{
			Status: "DOWN",
			Db:     "unreachable",
		})
		return
	}

	err = sqlDB.Ping()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, HealthCheckResponse{
			Status: "DOWN",
			Db:     "unreachable",
		})
		return
	}

	c.JSON(http.StatusOK, HealthCheckResponse{
		Status: "UP",
		Db:     "Reachable",
	})
}

// replace this "" from the begining of json and at the end with  backtip

type HealthCheckResponse struct {
	Status string ` + "`" + `json:"status"` + "`" + `
	Db     string ` + "`" + `json:"db"` + "`" + `
}

	`,
	)
}

func appEnv() string {
	return fmt.Sprintf(`
DATABASE_URL=DB_CONNECTION
APP_PORT=0.0.0.0:8080
SECRET_KEY=APP_SECRET
	`,
	)
}

func ignore() string {
	return fmt.Sprintf(`
	 app.env
	`,
	)
}

func main(packageName string) string {
	return fmt.Sprintf(`
package main

import (
	"%s/cmd"
)

// INFO
// 1. Run go mod init <then the project name you prodided>
// 2. Run go mod tidy
// 3. Read through the instruction of every page to understand the code
// 4. Before starting your server ensure you have changed your database_url in app.env
func main() {
	cmd.Execute()
}`, packageName)
}
