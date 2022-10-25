package consul

import (
	"encoding/json"
	"fmt"
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/hashicorp/consul/api"
	"os"
)

type ConsulAuthRepository struct {
	cli *api.Client
}

func NewConsulAuthRepository() (*ConsulAuthRepository, error) {
	db := os.Getenv("DB")
	dbport := os.Getenv("DBPORT")

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("%s:%s", db, dbport)
	client, err := api.NewClient(config)

	if err != nil {
		return nil, err
	}

	car := ConsulAuthRepository{
		cli: client,
	}

	return &car, nil
}

func (r *ConsulAuthRepository) UsernameExists(username string) (bool, error) {
	kv := r.cli.KV()

	userKey := fmt.Sprintf("user/%s/", username)

	data, _, err := kv.List(userKey, nil)

	if err != nil {
		return false, err
	}

	if data == nil {
		return false, nil
	}

	return true, nil
}

func (r *ConsulAuthRepository) GetUser(username string) (*model.User, error) {
	return &model.User{}, nil
}

func (r *ConsulAuthRepository) SaveUser(pr *model.User) error {
	data, err := json.Marshal(pr)
	if err != nil {
		return err
	}

	kv := r.cli.KV()

	userKey := fmt.Sprintf("user/%s/", pr.Username)

	p := &api.KVPair{Key: userKey, Value: data}

	_, err = kv.Put(p, nil)

	return nil
}

func (r *ConsulAuthRepository) SaveVerification(uuid string, username string) error {
	return nil
}

func (r *ConsulAuthRepository) GetVerification(uuid string) (string, error) {
	return "verification", nil
}

func (r *ConsulAuthRepository) DeleteVerification(u *model.User) error {
	return nil
}
