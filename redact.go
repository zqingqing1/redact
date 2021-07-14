package redact

import (
	"errors"
	"reflect"
)

const (
	tagName        = "redact"
	RedactStrConst = "REDACTED"
)

type redactor func(string) string

var redactors = map[string]redactor{}

// AddRedactor allows for adding custom functionality based on tag values
func AddRedactor(key string, r redactor) {
	redactors[key] = r
}

// Redact redacts all strings without the nonsecret tag
func Redact(iface interface{}) error {
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
		case reflect.Struct:
			if el.CanAddr() && el.Addr().CanInterface() {
				Redact(el.Addr().Interface())
			}
		case reflect.String:
			if el.CanSet() {
				tagVal := v.Tag.Get(tagName)
				input := el.String()
				el.SetString(transformString(input, tagVal))
			}
		default:
			tagVal := v.Tag.Get(tagName)
			if el.CanAddr() && el.Addr().CanInterface() {
				redactHelper(el.Addr().Interface(), tagVal)
			}

		}
	}
	return nil
}

func redactHelper(iface interface{}, tagVal string) error {
	ifv := reflect.ValueOf(iface)
	if ifv.Kind() != reflect.Ptr {
		return errors.New("Not a pointer")
	}

	ifIndirectValue := reflect.Indirect(ifv)
	switch ifIndirectValue.Kind() {
	case reflect.Slice:
		if ifIndirectValue.CanInterface() {
			elType := getSliceElemType(ifIndirectValue.Type())

			// allow strings and string pointers
			str := ""
			if (elType.ConvertibleTo(reflect.TypeOf(str)) && reflect.TypeOf(str).ConvertibleTo(elType)) ||
				(elType.ConvertibleTo(reflect.TypeOf(&str)) && reflect.TypeOf(&str).ConvertibleTo(elType)) {
				for i := 0; i < ifIndirectValue.Len(); i++ {
					ifIndirectValue.Index(i).Set(transformValue(tagVal, ifIndirectValue.Index(i)))
				}
			} else {
				val := reflect.ValueOf(ifIndirectValue.Interface())
				for i := 0; i < val.Len(); i++ {
					elVal := val.Index(i)
					if elVal.Kind() != reflect.Ptr {
						elVal = elVal.Addr()
					}
					redactHelper(elVal.Interface(), tagVal)
				}
			}
		}
	case reflect.Map:
		if ifIndirectValue.CanInterface() {
			val := reflect.ValueOf(ifIndirectValue.Interface())
			for _, key := range val.MapKeys() {
				mapValue := val.MapIndex(key)
				mapValuePtr := reflect.New(mapValue.Type())
				mapValuePtr.Elem().Set(mapValue)
				if mapValuePtr.Elem().CanAddr() {
					redactHelper(mapValuePtr.Elem().Addr().Interface(), tagVal)
				}
				val.SetMapIndex(key, reflect.Indirect(mapValuePtr))
			}
		}
	case reflect.Struct:
		if ifIndirectValue.CanAddr() && ifIndirectValue.Addr().CanInterface() {
			Redact(ifIndirectValue.Addr().Interface())
		}
	case reflect.String:
		if ifIndirectValue.CanSet() {
			input := ifIndirectValue.String()
			ifIndirectValue.SetString(transformString(input, tagVal))
		}
	case reflect.Ptr:
		if ifIndirectValue.CanInterface() {
			redactHelper(ifIndirectValue.Interface(), tagVal)
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
		redactor, ok := redactors[tagVal]
		if !ok {
			return RedactStrConst
		}

		return redactor(input)
	}
}
