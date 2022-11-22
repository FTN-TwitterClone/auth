package validation

import (
	"bufio"
	"github.com/go-playground/validator/v10"
	"log"
	"os"
	"reflect"
	"unicode"
)

var blacklist map[string]bool

func init() {
	blacklist = make(map[string]bool, 10000)

	blacklistPath := os.Getenv("PASS_BLACKLIST")

	file, err := os.Open(blacklistPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		blacklist[scanner.Text()] = true
	}
}

func ValidatePassword(fl validator.FieldLevel) bool {
	field := fl.Field()

	if field.Kind() != reflect.String {
		return false
	}

	if !validateContent(field.String()) {
		return false
	}

	return validateBlacklist(field.String())
}

func validateContent(password string) bool {
	var (
		upp, low, num, sym bool
		tot                uint8
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			upp = true
			tot++
		case unicode.IsLower(char):
			low = true
			tot++
		case unicode.IsNumber(char):
			num = true
			tot++
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			sym = true
			tot++
		default:
			return false
		}
	}

	if !upp || !low || !num || !sym || tot < 8 {
		return false
	}

	return true
}

func validateBlacklist(password string) bool {
	if _, ok := blacklist[password]; ok {
		return false
	}

	return true
}
