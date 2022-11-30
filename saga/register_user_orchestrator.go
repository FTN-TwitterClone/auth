package saga

import (
	"fmt"
	"github.com/FTN-TwitterClone/auth/repository"
	"github.com/nats-io/nats.go"
	"os"
)

type RegisterUserOrchestrator struct {
	conn           *nats.EncodedConn
	authRepository repository.AuthRepository
}

func NewRegisterUserOrchestrator(authRepository repository.AuthRepository) (*RegisterUserOrchestrator, error) {
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

	_, err = encConn.Subscribe("sub", o.handleReply)
	if err != nil {
		return nil, err
	}

	return o, nil
}

func (o RegisterUserOrchestrator) Start() {

}

func (o RegisterUserOrchestrator) handleReply(m *nats.Msg) {

}
