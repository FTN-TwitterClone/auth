package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/FTN-TwitterClone/auth/controller"
	"github.com/FTN-TwitterClone/auth/controller/jwt"
	"github.com/FTN-TwitterClone/auth/repository/consul"
	"github.com/FTN-TwitterClone/auth/service"
	"github.com/FTN-TwitterClone/auth/tracing"
	"github.com/gorilla/mux"
	grpcpool "github.com/processout/grpc-go-pool"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io/ioutil"
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
		//log.Fatal(err)
	}

	profileAddr := "profile:9001"

	var factory grpcpool.Factory
	factory = func() (*grpc.ClientConn, error) {
		conn, err := grpc.DialContext(
			context.Background(),
			profileAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		)
		if err != nil {
			log.Fatalf("Failed to start gRPC connection: %v", err)
		}
		log.Println("Connected to employee at %s", profileAddr)
		return conn, err
	}

	pool, err := grpcpool.New(factory, 5, 5, time.Second)
	if err != nil {
		log.Fatalf("Failed to create gRPC pool: %v", err)
	}

	authService := service.NewAuthService(tracer, authRepository, pool)

	authController := controller.NewAuthController(tracer, authService)

	router := mux.NewRouter()
	router.StrictSlash(true)
	router.Use(
		tracing.ExtractTraceInfoMiddleware,
		mux.CORSMethodMiddleware(router),
		jwt.ExtractJWTUserMiddleware(tracer),
	)

	router.HandleFunc("/register/user/", authController.RegisterUser).Methods("POST")
	router.HandleFunc("/register/business/", authController.RegisterBusinessUser).Methods("POST")
	router.HandleFunc("/login/", authController.LoginUser).Methods("POST")
	router.HandleFunc("/verify/{verificationId}/", authController.VerifyRegistration).Methods("PUT")

	// start server
	srv := &http.Server{
		Addr:    "0.0.0.0:8000",
		Handler: router,
		//TLSConfig: getTLSConfig(),
	}

	go func() {
		log.Println("server starting")

		//certFile := os.Getenv("CERT")
		//keyFile := os.Getenv("KEY")

		if err := srv.ListenAndServe(); err != nil {
			//if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
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

func getTLSConfig() *tls.Config {
	var caCert []byte
	var err error
	var caCertPool *x509.CertPool

	caCert, err = ioutil.ReadFile(os.Getenv("CA_CERT"))
	if err != nil {
		log.Fatal("Error opening cert file", err)
	}
	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		ServerName: "auth",
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12, // TLS versions below 1.2 are considered insecure - see https://www.rfc-editor.org/rfc/rfc7525.txt for details
	}
}
