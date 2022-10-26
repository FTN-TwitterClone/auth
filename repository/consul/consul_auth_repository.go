package consul

import (
	"encoding/json"
	"errors"
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
	kv := r.cli.KV()

	userKey := fmt.Sprintf("user/%s/", username)

	pair, _, err := kv.Get(userKey, nil)
	if err != nil {
		return &model.User{}, err
	}

	if pair == nil {
		return &model.User{}, errors.New("Username doesn't exist!")
	}

	user := model.User{}
	err = json.Unmarshal(pair.Value, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
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
	if err != nil {
		return err
	}

	return nil
}

func (r *ConsulAuthRepository) SaveVerification(uuid string, username string) error {
	kv := r.cli.KV()

	verificationKey := fmt.Sprintf("verification/%s/", uuid)

	p := &api.KVPair{Key: verificationKey, Value: []byte(username)}

	_, err := kv.Put(p, nil)
	if err != nil {
		return err
	}

	return nil
}

func (r *ConsulAuthRepository) GetVerification(uuid string) (string, error) {
	kv := r.cli.KV()

	verificationKey := fmt.Sprintf("verification/%s/", uuid)

	pair, _, err := kv.Get(verificationKey, nil)
	if err != nil {
		return "", err
	}

	if pair == nil {
		return "", errors.New("Verification doesn't exist!")
	}

	return string(pair.Value), nil
}

func (r *ConsulAuthRepository) DeleteVerification(uuid string) error {
	kv := r.cli.KV()

	verificationKey := fmt.Sprintf("verification/%s/", uuid)

	_, err := kv.Delete(verificationKey, nil)
	if err != nil {
		return err
	}

	return nil
}
