package route

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
)

func parseTx(body io.ReadCloser) string {
	value, err := ioutil.ReadAll(body)
	if err != nil {
		fmt.Println(err.Error())
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(value), &data)

	return data["tx"].(string)
}
