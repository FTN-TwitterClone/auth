package main

import (
	"context"
	"github.com/FTN-TwitterClone/auth/controller"
	"github.com/FTN-TwitterClone/auth/controller/jwt"
	"github.com/FTN-TwitterClone/auth/email"
	"github.com/FTN-TwitterClone/auth/repository/consul"
	"github.com/FTN-TwitterClone/auth/saga"
	"github.com/FTN-TwitterClone/auth/service"
	"github.com/FTN-TwitterClone/auth/tls"
	"github.com/FTN-TwitterClone/auth/tracing"
	"github.com/gorilla/handlers"
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

	emailSender := email.NewEmailSender(tracer)

	registerUserOrchestrator, err := saga.NewRegisterUserOrchestrator()
	if err != nil {
		log.Fatal(err)
	}

	_, err = saga.NewRegisterUserHandler(authRepository, emailSender)
	if err != nil {
		log.Fatal(err)
	}

	authService := service.NewAuthService(tracer, authRepository, emailSender, registerUserOrchestrator)

	authController := controller.NewAuthController(tracer, authService)

	router := mux.NewRouter()
	router.StrictSlash(true)
	router.Use(
		tracing.ExtractTraceInfoMiddleware,
		jwt.ExtractJWTUserMiddleware(tracer),
	)

	router.HandleFunc("/register/user/", authController.RegisterUser).Methods("POST")
	router.HandleFunc("/register/business/", authController.RegisterBusinessUser).Methods("POST")
	router.HandleFunc("/login/", authController.LoginUser).Methods("POST")
	router.HandleFunc("/verify/{verificationId}/", authController.VerifyRegistration).Methods("PUT")
	router.HandleFunc("/password/change/", authController.ChangePassword).Methods("PUT")
	router.HandleFunc("/account/{username}/recover/", authController.RequestAccountRecovery).Methods("PUT")
	router.HandleFunc("/recover/{recoveryId}/", authController.RecoverAccount).Methods("PUT")

	allowedHeaders := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	allowedMethods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "HEAD", "OPTIONS"})
	allowedOrigins := handlers.AllowedOrigins([]string{"*"})

	// start server
	srv := &http.Server{
		Addr:      "0.0.0.0:8000",
		Handler:   handlers.CORS(allowedHeaders, allowedMethods, allowedOrigins)(router),
		TLSConfig: tls.GetHTTPServerTLSConfig(),
	}

	go func() {
		log.Println("server starting")

		certFile := os.Getenv("CERT")
		keyFile := os.Getenv("KEY")

		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
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
