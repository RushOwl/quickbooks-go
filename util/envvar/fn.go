package envvar

import "os"

func GetEnvVar(evType envVarType) (value string, isExist bool) {
	value = os.Getenv(string(evType))
	isExist = value != ""
	return
}
