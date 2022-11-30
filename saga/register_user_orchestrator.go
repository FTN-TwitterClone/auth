package saga

import (
	"fmt"
	"github.com/FTN-TwitterClone/auth/email"
	"github.com/FTN-TwitterClone/auth/repository"
	"github.com/nats-io/nats.go"
	"log"
	"os"
)

const (
	REGISTER_COMMAND = "register.reply"
	REGISTER_REPLY   = "register.command"
)

type RegisterUserOrchestrator struct {
	conn           *nats.EncodedConn
	authRepository repository.AuthRepository
	emailSender    *email.EmailSender
}

func NewRegisterUserOrchestrator(authRepository repository.AuthRepository, emailSender *email.EmailSender) (*RegisterUserOrchestrator, error) {
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

	o := &RegisterUserOrchestrator{
		conn:           encConn,
		authRepository: authRepository,
	}

	_, err = encConn.Subscribe(REGISTER_REPLY, o.handleReply)
	if err != nil {
		return nil, err
	}

	return o, nil
}

func (o RegisterUserOrchestrator) Start() {
	err := o.conn.Publish(REGISTER_COMMAND, []byte("hello world!"))
	if err != nil {
		log.Fatal(err)
	}
}

func (o RegisterUserOrchestrator) handleReply(m *nats.Msg) {
	//TODO: read from message

	r := ProfileSuccess

	switch r {
	case ProfileSuccess:
		println(SaveSocialGraph)
	case ProfileFail:
		//TODO: is it necessary to send message to myself?
		println("local rollback")
		o.sendUserVerification()
	case ProfileRollback:
		//TODO: is it necessary to send message to myself?
		println("local rollback")
		o.sendUserVerification()
	case SocialGraphSuccess:
		println(3)
	case SocialGraphFail:
		println(RollbackProfile)
	}
}

func (o RegisterUserOrchestrator) handleSocialGraphFail(m *nats.Msg) {

}

func (o RegisterUserOrchestrator) handleSocialGraphSuccess(m *nats.Msg) {

}

func (o RegisterUserOrchestrator) sendUserVerification() {
	//verificationId := uuid.New().String()
	//err = s.authRepository.SaveVerification(, verificationId, u.Username)
	//if err != nil {
	//	span.SetStatus(codes.Error, err.Error())
	//	return &app_errors.AppError{500, ""}
	//}
	//
	//go o.emailSender.SendVerificationEmail(serviceCtx, user.Email, verificationId)
}
