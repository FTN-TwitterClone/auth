package saga

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/FTN-TwitterClone/auth/email"
	"github.com/FTN-TwitterClone/auth/repository"
	"github.com/FTN-TwitterClone/auth/tracing"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"os"
)

type RegisterUserHandler struct {
	tracer         trace.Tracer
	conn           *nats.Conn
	authRepository repository.AuthRepository
	emailSender    *email.EmailSender
}

func NewRegisterUserHandler(tracer trace.Tracer, authRepository repository.AuthRepository, emailSender *email.EmailSender) (*RegisterUserHandler, error) {
	natsHost := os.Getenv("NATS_HOST")
	natsPort := os.Getenv("NATS_PORT")

	url := fmt.Sprintf("nats://%s:%s", natsHost, natsPort)

	connection, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}

	h := &RegisterUserHandler{
		tracer:         tracer,
		conn:           connection,
		authRepository: authRepository,
		emailSender:    emailSender,
	}

	_, err = connection.Subscribe(REGISTER_COMMAND, h.handleCommand)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h RegisterUserHandler) handleCommand(msg *nats.Msg) {
	remoteCtx, err := tracing.GetNATSParentContext(msg)
	if err != nil {

	}

	ctx, span := otel.Tracer("auth").Start(trace.ContextWithRemoteSpanContext(context.Background(), remoteCtx), "RegisterUserHandler.handleCommand")
	defer span.End()

	var c RegisterUserCommand

	err = json.Unmarshal(msg.Data, &c)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return
	}

	switch c.Command {
	case ConfirmAuth:
		h.handleConfirmAuth(ctx, c.User)
	case RollbackAuth:
		h.handleRollbackAuth(ctx, c.User)
	}
}

func (h RegisterUserHandler) handleConfirmAuth(ctx context.Context, user NewUser) {
	handlerCtx, span := h.tracer.Start(ctx, "RegisterUserHandler.handleConfirmAuth")
	defer span.End()

	verificationId := uuid.New().String()
	err := h.authRepository.SaveVerification(handlerCtx, verificationId, user.Username)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	}

	go h.emailSender.SendVerificationEmail(handlerCtx, user.Email, verificationId)
}

func (h RegisterUserHandler) handleRollbackAuth(ctx context.Context, user NewUser) {
	_, span := h.tracer.Start(ctx, "RegisterUserHandler.handleRollbackAuth")
	defer span.End()
}
