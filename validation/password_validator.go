package validation

import (
	"github.com/go-playground/validator/v10"
	"reflect"
	"unicode"
)

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
	return true
}
