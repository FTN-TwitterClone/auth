package saga

import (
	"fmt"
	"github.com/nats-io/nats.go"
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
	c := RegisterUserCommand{
		Command: SaveProfile,
		User:    user,
	}

	o.sendCommand(c)
}

func (o RegisterUserOrchestrator) handleReply(r RegisterUserReply) {
	switch r.Reply {
	case ProfileSuccess:
		o.sendCommand(RegisterUserCommand{
			Command: SaveSocialGraph,
			User:    r.User,
		})
	case ProfileFail:
		o.sendCommand(RegisterUserCommand{
			Command: RollbackAuth,
			User:    r.User,
		})
	case ProfileRollback:
		o.sendCommand(RegisterUserCommand{
			Command: RollbackAuth,
			User:    r.User,
		})
	case SocialGraphSuccess:
		o.sendCommand(RegisterUserCommand{
			Command: ConfirmAuth,
			User:    r.User,
		})
	case SocialGraphFail:
		o.sendCommand(RegisterUserCommand{
			Command: RollbackProfile,
			User:    r.User,
		})
	}
}

func (o RegisterUserOrchestrator) sendCommand(c RegisterUserCommand) {
	err := o.conn.Publish(REGISTER_COMMAND, c)
	if err != nil {
		//TODO: error
	}
}
