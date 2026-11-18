package config

import (
	"fmt"
	"reflect"
	"strings"
)

// exactKeys refuses any key in a configuration layer that is not exactly the
// JSON name of a Config field. Go's JSON decoding matches names without regard
// to case (and folds ſ to s), so "allowsign" would set allowSign while the
// byte-exact lock check missed it (security review R1). Every layer is held to
// the spelling the schema documents.
func exactKeys(m map[string]any, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	fields := jsonFields(t)
	for k, v := range m {
		ft, ok := fields[k]
		if !ok {
			return fmt.Errorf("%s: unknown key %q (keys are case-sensitive)", strings.TrimPrefix(path+"."+k, "."), k)
		}
		if err := exactValue(v, ft, strings.TrimPrefix(path+"."+k, ".")); err != nil {
			return err
		}
	}
	return nil
}

func exactValue(v any, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if mv, ok := v.(map[string]any); ok {
			return exactKeys(mv, t, path)
		}
	case reflect.Slice, reflect.Array:
		if lv, ok := v.([]any); ok {
			for i, e := range lv {
				if err := exactValue(e, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		if mv, ok := v.(map[string]any); ok {
			for k, e := range mv {
				if err := exactValue(e, t.Elem(), path+"."+k); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// jsonFields maps each JSON name of t's fields (embedded structs included)
// to the field's type.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			et := f.Type
			for et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				for k, v := range jsonFields(et) {
					out[k] = v
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}
