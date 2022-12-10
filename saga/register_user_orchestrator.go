package saga

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/FTN-TwitterClone/auth/tracing"
	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"os"
)

type RegisterUserOrchestrator struct {
	tracer trace.Tracer
	conn   *nats.Conn
}

func NewRegisterUserOrchestrator(tracer trace.Tracer) (*RegisterUserOrchestrator, error) {
	natsHost := os.Getenv("NATS_HOST")
	natsPort := os.Getenv("NATS_PORT")

	url := fmt.Sprintf("nats://%s:%s", natsHost, natsPort)

	connection, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}

	o := &RegisterUserOrchestrator{
		tracer: tracer,
		conn:   connection,
	}

	_, err = connection.Subscribe(REGISTER_REPLY, o.handleReply)
	if err != nil {
		return nil, err
	}

	return o, nil
}

func (o RegisterUserOrchestrator) Start(ctx context.Context, user NewUser) {
	orchestratorCtx, span := o.tracer.Start(ctx, "RegisterUserOrchestrator.Start")
	defer span.End()

	c := RegisterUserCommand{
		Command: SaveProfile,
		User:    user,
	}

	o.sendCommand(orchestratorCtx, c)
}

func (o RegisterUserOrchestrator) handleReply(msg *nats.Msg) {
	remoteCtx, err := tracing.GetNATSParentContext(msg)
	if err != nil {

	}

	orchestratorCtx, span := otel.Tracer("auth").Start(trace.ContextWithRemoteSpanContext(context.Background(), remoteCtx), "RegisterUserOrchestrator.handleReply")
	defer span.End()

	var r RegisterUserReply

	err = json.Unmarshal(msg.Data, &r)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return
	}

	switch r.Reply {
	case ProfileSuccess:
		o.sendCommand(orchestratorCtx, RegisterUserCommand{
			Command: SaveSocialGraph,
			User:    r.User,
		})
	case ProfileFail:
		o.sendCommand(orchestratorCtx, RegisterUserCommand{
			Command: RollbackAuth,
			User:    r.User,
		})
	case ProfileRollback:
		o.sendCommand(orchestratorCtx, RegisterUserCommand{
			Command: RollbackAuth,
			User:    r.User,
		})
	case SocialGraphSuccess:
		o.sendCommand(orchestratorCtx, RegisterUserCommand{
			Command: ConfirmAuth,
			User:    r.User,
		})
	case SocialGraphFail:
		o.sendCommand(orchestratorCtx, RegisterUserCommand{
			Command: RollbackProfile,
			User:    r.User,
		})
	}
}

func (o RegisterUserOrchestrator) sendCommand(ctx context.Context, c RegisterUserCommand) {
	_, span := o.tracer.Start(ctx, "RegisterUserOrchestrator.sendCommand")
	defer span.End()

	headers := nats.Header{}
	headers.Set(tracing.TRACE_ID, span.SpanContext().TraceID().String())
	headers.Set(tracing.SPAN_ID, span.SpanContext().SpanID().String())

	data, err := json.Marshal(c)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return
	}

	msg := nats.Msg{
		Subject: REGISTER_COMMAND,
		Header:  headers,
		Data:    data,
	}

	err = o.conn.PublishMsg(&msg)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	}
}
