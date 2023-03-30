package keyinfo

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

func GetKeyName(key string) string {
	jsonFile, err := os.Open("./keyinfo.json")
	if err != nil {
		fmt.Println(err)
	}

	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	keyinfo := make(map[string]interface{})

	err = json.Unmarshal(byteValue, &keyinfo)
	if err != nil {
		fmt.Println(err)
	}

	keynames := keyinfo["keynames"].(map[string]interface{})

	return keynames[key].(string)
}
