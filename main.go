package main

import (
	"context"
	"github.com/FTN-TwitterClone/auth/controller"
	"github.com/FTN-TwitterClone/auth/repository/consul"
	"github.com/FTN-TwitterClone/auth/service"
	"github.com/FTN-TwitterClone/auth/tracer"
	"github.com/gorilla/mux"
	"github.com/opentracing/opentracing-go"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	tracer, closer := tracer.Init("auth_service")
	opentracing.SetGlobalTracer(tracer)

	authRepository, err := consul.NewConsulAuthRepository()
	if err != nil {
		log.Fatal(err)
	}

	authService := service.NewAuthService(authRepository)

	authController := controller.NewAuthController(authService)

	router := mux.NewRouter()
	router.StrictSlash(true)

	router.HandleFunc("/register/", authController.RegisterUser).Methods("POST")
	router.HandleFunc("/login/", authController.LoginUser).Methods("POST")
	router.HandleFunc("/verify/{verificationId}/", authController.VerifyRegistration).Methods("PUT")

	// start server
	srv := &http.Server{Addr: "0.0.0.0:8001", Handler: router}
	go func() {
		log.Println("server starting")
		if err := srv.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}
	}()

	<-quit

	log.Println("service shutting down ...")

	// gracefully stop server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
	log.Println("server stopped")

	if err := closer.Close(); err != nil {
		log.Fatal(err)
	}
	log.Println("traces saved")
}
