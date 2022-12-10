package json

import (
	"encoding/json"
	"io"
	"net/http"
)

func EncodeJson(w http.ResponseWriter, v interface{}) error {
	js, err := json.Marshal(v)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/model")
	w.Write(js)

	return nil
}

func DecodeJson[V any](r io.Reader) (V, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt V
	if err := dec.Decode(&rt); err != nil {
		return rt, err
	}

	return rt, nil
}
