package jwt

import (
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel/trace"
	"net/http"
)

func ExtractJWTUserMiddleware(tracer trace.Tracer) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			newCtx, span := tracer.Start(r.Context(), "ExtractJWTUserMiddleware")
			defer span.End()

			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}
}
