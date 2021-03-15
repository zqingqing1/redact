package redact

import (
	"errors"
	"reflect"
)

const (
	tagName = "redact"
)

type sanitizer func(string) string

var sanitizers = map[string]sanitizer{}

// AddSanitizer associates a sanitizer with a key, which can be used in a Struct tag
func AddSanitizer(key string, s sanitizer) {
	sanitizers[key] = s
}

// Strings conforms strings based on reflection tags
func Strings(iface interface{}) error {
	ifv := reflect.ValueOf(iface)
	if ifv.Kind() != reflect.Ptr {
		return errors.New("Not a pointer")
	}
	ift := reflect.Indirect(ifv).Type()
	if ift.Kind() != reflect.Struct {
		return nil
	}
	for i := 0; i < ift.NumField(); i++ {
		v := ift.Field(i)
		el := reflect.Indirect(ifv.Elem().FieldByName(v.Name))
		switch el.Kind() {
		case reflect.Slice:
			if el.CanInterface() {
				elType := getSliceElemType(v.Type)

				// allow strings and string pointers
				str := ""
				if (elType.ConvertibleTo(reflect.TypeOf(str)) && reflect.TypeOf(str).ConvertibleTo(elType)) ||
					(elType.ConvertibleTo(reflect.TypeOf(&str)) && reflect.TypeOf(&str).ConvertibleTo(elType)) {
					tags := v.Tag.Get(tagName)
					for i := 0; i < el.Len(); i++ {
						el.Index(i).Set(transformValue(tags, el.Index(i)))
					}
				} else {
					val := reflect.ValueOf(el.Interface())
					for i := 0; i < val.Len(); i++ {
						elVal := val.Index(i)
						if elVal.Kind() != reflect.Ptr {
							elVal = elVal.Addr()
						}
						Strings(elVal.Interface())
					}
				}
			}
		case reflect.Map:
			if el.CanInterface() {
				val := reflect.ValueOf(el.Interface())
				for _, key := range val.MapKeys() {
					mapValue := val.MapIndex(key)
					mapValuePtr := reflect.New(mapValue.Type())
					mapValuePtr.Elem().Set(mapValue)
					if mapValuePtr.Elem().CanAddr() {
						Strings(mapValuePtr.Elem().Addr().Interface())
					}
					val.SetMapIndex(key, reflect.Indirect(mapValuePtr))
				}
			}
		case reflect.Struct:
			if el.CanAddr() && el.Addr().CanInterface() {
				// To handle "sql.NullString" we can assume that tags are added to a field of type struct rather than string
				if tags := v.Tag.Get(tagName); tags != "" && el.CanSet() {
					field := el.FieldByName("String")
					str := field.String()
					field.SetString(transformString(str, tags))
				} else {
					Strings(el.Addr().Interface())
				}
			}
		case reflect.String:
			if el.CanSet() {
				tags := v.Tag.Get(tagName)
				input := el.String()
				el.SetString(transformString(input, tags))
			}
		}
	}
	return nil
}

func getSliceElemType(t reflect.Type) reflect.Type {
	var elType reflect.Type
	if t.Kind() == reflect.Ptr {
		elType = t.Elem().Elem()
	} else {
		elType = t.Elem()
	}

	return elType
}

func transformValue(tags string, val reflect.Value) reflect.Value {
	if val.Kind() == reflect.Ptr && val.IsNil() {
		return val
	}

	var oldStr string
	if val.Kind() == reflect.Ptr {
		oldStr = val.Elem().String()
	} else {
		oldStr = val.String()
	}

	newStr := transformString(oldStr, tags)

	var newVal reflect.Value
	if val.Kind() == reflect.Ptr {
		newVal = reflect.ValueOf(&newStr)
	} else {
		newVal = reflect.ValueOf(newStr)
	}

	return newVal.Convert(val.Type())
}

func transformString(input, tagVal string) string {
	switch tagVal {
	case "nonsecret":
		return input
	default:
		s, ok := sanitizers[tagVal]
		if !ok {
			return "REDACTED"
		}

		return s(input)
	}
}
