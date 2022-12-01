package saga

import (
	"fmt"
	"github.com/nats-io/nats.go"
	"log"
	"os"
)

type RegisterUserOrchestrator struct {
	conn *nats.EncodedConn
}

func NewRegisterUserOrchestrator() (*RegisterUserOrchestrator, error) {
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
		conn: encConn,
	}

	_, err = encConn.Subscribe(REGISTER_REPLY, o.handleReply)
	if err != nil {
		return nil, err
	}

	return o, nil
}

func (o RegisterUserOrchestrator) Start(user NewUser) {
	//c :=

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
		println(RollbackAuth)
	case ProfileRollback:
		println(RollbackAuth)
	case SocialGraphSuccess:
		println(ConfirmAuth)
	case SocialGraphFail:
		println(RollbackProfile)
	}
}
