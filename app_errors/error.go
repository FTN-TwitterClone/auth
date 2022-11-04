package app_errors

import "fmt"

type AppError struct {
	Code    int
	Message string
}

func (e AppError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}
