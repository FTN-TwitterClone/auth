package consul

import (
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

func (r *ConsulAuthRepository) SaveUser(u model.User) error {
	return nil
}
