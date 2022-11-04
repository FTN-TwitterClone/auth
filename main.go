package main

import (
	"context"
	"github.com/FTN-TwitterClone/auth/controller"
	"github.com/FTN-TwitterClone/auth/repository/consul"
	"github.com/FTN-TwitterClone/auth/service"
	"github.com/FTN-TwitterClone/auth/tracing"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
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

	ctx := context.Background()
	exp, err := tracing.NewExporter()
	if err != nil {
		log.Fatalf("failed to initialize exporter: %v", err)
	}
	// Create a new tracer provider with a batch span processor and the given exporter.
	tp := tracing.NewTraceProvider(exp)
	// Handle shutdown properly so nothing leaks.
	defer func() { _ = tp.Shutdown(ctx) }()
	otel.SetTracerProvider(tp)
	// Finally, set the tracer that can be used for this package.
	tracer := tp.Tracer("auth")
	otel.SetTextMapPropagator(propagation.TraceContext{})

	authRepository, err := consul.NewConsulAuthRepository(tracer)
	if err != nil {
		log.Fatal(err)
	}

	authService := service.NewAuthService(tracer, authRepository)

	authController := controller.NewAuthController(tracer, authService)

	router := mux.NewRouter()
	router.StrictSlash(true)
	router.Use(tracing.ExtractTraceInfoMiddleware)

	router.HandleFunc("/register/", authController.RegisterUser).Methods("POST")
	router.HandleFunc("/login/", authController.LoginUser).Methods("POST")
	router.HandleFunc("/verify/{verificationId}/", authController.VerifyRegistration).Methods("PUT")

	// start server
	srv := &http.Server{Addr: "0.0.0.0:8000", Handler: router}
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
}
