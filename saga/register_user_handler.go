package saga

import (
	"fmt"
	"github.com/FTN-TwitterClone/auth/email"
	"github.com/FTN-TwitterClone/auth/repository"
	"github.com/nats-io/nats.go"
	"os"
)

type RegisterUserHandler struct {
	conn           *nats.EncodedConn
	authRepository repository.AuthRepository
	emailSender    *email.EmailSender
}

func NewRegisterUserHandler(authRepository repository.AuthRepository, emailSender *email.EmailSender) (*RegisterUserHandler, error) {
	natsHost := os.Getenv("NATS_HOST")
	natsPort := os.Getenv("NATS_PORT")

	url := fmt.Sprintf("nats://%s:%s", natsHost, natsPort)

	connection, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}

	encConn, err := nats.NewEncodedConn(connection, nats.JSON_ENCODER)
	if err != nil {
		return nil, err
	}

	h := &RegisterUserHandler{
		conn:           encConn,
		authRepository: authRepository,
		emailSender:    emailSender,
	}

	_, err = encConn.Subscribe(REGISTER_COMMAND, h.handleCommand)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h RegisterUserHandler) handleCommand(m *nats.Msg) {

}

func (h RegisterUserHandler) handleSocialGraphFail(m *nats.Msg) {

}

func (h RegisterUserHandler) handleSocialGraphSuccess(m *nats.Msg) {

}

func (h RegisterUserHandler) sendUserVerification() {
	//verificationId := uuid.New().String()
	//err = s.authRepository.SaveVerification(, verificationId, u.Username)
	//if err != nil {
	//	span.SetStatus(codes.Error, err.Error())
	//	return &app_errors.AppError{500, ""}
	//}
	//
	//go o.emailSender.SendVerificationEmail(serviceCtx, user.Email, verificationId)
}
