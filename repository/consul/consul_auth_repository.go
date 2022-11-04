package consul

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/hashicorp/consul/api"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"os"
)

type ConsulAuthRepository struct {
	tracer trace.Tracer
	cli    *api.Client
}

func NewConsulAuthRepository(tracer trace.Tracer) (*ConsulAuthRepository, error) {
	db := os.Getenv("DB")
	dbport := os.Getenv("DBPORT")

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("%s:%s", db, dbport)
	client, err := api.NewClient(config)

	if err != nil {
		return nil, err
	}

	car := ConsulAuthRepository{
		tracer,
		client,
	}

	return &car, nil
}

func (r *ConsulAuthRepository) UsernameExists(ctx context.Context, username string) (bool, error) {
	_, span := r.tracer.Start(ctx, "ConsulAuthRepository.UsernameExists")
	defer span.End()

	kv := r.cli.KV()

	userKey := fmt.Sprintf("user/%s/", username)

	data, _, err := kv.List(userKey, nil)

	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}

	if data == nil {
		return false, nil
	}

	return true, nil
}

func (r *ConsulAuthRepository) GetUser(ctx context.Context, username string) (*model.User, error) {
	_, span := r.tracer.Start(ctx, "ConsulAuthRepository.GetUser")
	defer span.End()

	kv := r.cli.KV()

	userKey := fmt.Sprintf("user/%s/", username)

	pair, _, err := kv.Get(userKey, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &model.User{}, err
	}

	if pair == nil {
		return &model.User{}, errors.New("Username doesn't exist!")
	}

	user := model.User{}
	err = json.Unmarshal(pair.Value, &user)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &user, nil
}

func (r *ConsulAuthRepository) SaveUser(ctx context.Context, pr *model.User) error {
	_, span := r.tracer.Start(ctx, "ConsulAuthRepository.SaveUser")
	defer span.End()

	data, err := json.Marshal(pr)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	kv := r.cli.KV()

	userKey := fmt.Sprintf("user/%s/", pr.Username)

	p := &api.KVPair{Key: userKey, Value: data}

	_, err = kv.Put(p, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

func (r *ConsulAuthRepository) SaveVerification(ctx context.Context, uuid string, username string) error {
	_, span := r.tracer.Start(ctx, "ConsulAuthRepository.SaveVerification")
	defer span.End()

	kv := r.cli.KV()

	verificationKey := fmt.Sprintf("verification/%s/", uuid)

	p := &api.KVPair{Key: verificationKey, Value: []byte(username)}

	_, err := kv.Put(p, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

func (r *ConsulAuthRepository) GetVerification(ctx context.Context, uuid string) (string, error) {
	_, span := r.tracer.Start(ctx, "ConsulAuthRepository.GetVerification")
	defer span.End()

	kv := r.cli.KV()

	verificationKey := fmt.Sprintf("verification/%s/", uuid)

	pair, _, err := kv.Get(verificationKey, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	if pair == nil {
		return "", errors.New("Verification doesn't exist!")
	}

	return string(pair.Value), nil
}

func (r *ConsulAuthRepository) DeleteVerification(ctx context.Context, uuid string) error {
	_, span := r.tracer.Start(ctx, "ConsulAuthRepository.DeleteVerification")
	defer span.End()

	kv := r.cli.KV()

	verificationKey := fmt.Sprintf("verification/%s/", uuid)

	_, err := kv.Delete(verificationKey, nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}
