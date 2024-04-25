package lazyjson

import (
	"encoding/json"
)

type JSON struct {
	a []interface{}
	m map[string]interface{}
	v interface{}
}

var empty = JSON{}

func (nj JSON) K(key string) JSON {
	if nj.empty() {
		return empty
	}

	return newJSON(nj.m[key])
}

func (nj JSON) I(index int) JSON {
	if nj.empty() || index < 0 || index >= len(nj.a) {
		return empty
	}
	return newJSON(nj.a[index])
}

func (nj JSON) Int(defaultV int) int {
	if v, ok := i2int(nj.v); ok {
		return v
	}
	if v, ok := i2float(nj.v); ok {
		return int(v)
	}
	return defaultV
}

func (nj JSON) Float(defaultV float64) float64 {
	if v, ok := i2float(nj.v); ok {
		return v
	}
	return defaultV
}

func (nj JSON) String(defaultV string) string {
	if v, ok := i2string(nj.v); ok {
		return v
	}
	return defaultV
}

func (nj JSON) Bool(defaultV bool) bool {
	if v, ok := i2bool(nj.v); ok {
		return v
	}
	return defaultV
}

func (nj JSON) MarshalJSON() ([]byte, error) {
	if nj.m != nil {
		return json.Marshal(nj.m)
	} else if nj.a != nil {
		return json.Marshal(nj.a)
	} else {
		return json.Marshal(nj.v)
	}
}

func (nj *JSON) UnmarshalJSON(data []byte) error {
	var i interface{}
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}

	switch v := i.(type) {
	case map[string]interface{}:
		nj.m = v
	case []interface{}:
		nj.a = v
	default:
		nj.v = i
	}

	return nil
}

func (nj JSON) Size() int {
	if nj.empty() {
		return 0
	}
	if nj.m != nil {
		return len(nj.m)
	}
	if nj.a != nil {
		return len(nj.a)
	}
	return 1
}

func (nj JSON) empty() bool {
	return nj.a == nil && nj.m == nil && nj.v == nil
}

func newJSON(i interface{}) JSON {
	if i == nil {
		return empty
	}

	switch v := i.(type) {
	case map[string]interface{}:
		return JSON{m: v}
	case []interface{}:
		return JSON{a: v}
	default:
		return JSON{v: i}
	}
}

func i2int(i interface{}) (int, bool) {
	switch v := i.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint8:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		return int(v), true
	}
	return 0, false
}

func i2bool(i interface{}) (bool, bool) {
	switch v := i.(type) {
	case bool:
		return v, true
	}
	return false, false
}

func i2float(i interface{}) (float64, bool) {
	switch v := i.(type) {
	case float32:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

func i2string(i interface{}) (string, bool) {
	switch v := i.(type) {
	case string:
		return v, true
	}
	return "", false
}

package lazyjson


func TestDemo(t *testing.T) {
	data := `{
		"str_key": "hello",
		"int_key": 2333,
		"float_key": 23.33,
		"bool_key": true,
		"map": {
			"key1": "val1",
			"key2": "val2",
			"arr": [1, 2, 3, 4, 5, 6],
			"map": {
				"key1": "val1",
				"key2": "val2"
			}
		},
		"arr": [
			{
				"key1": "key1"
			},
			{
				"key2": "key2"
			}]
	}`

	var j JSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		t.Fatal(err)
	}
	println(j.K("str_key").String(""))
	println(j.K("int_key").Int(0))
	println(j.K("float_key").Float(0))
	println(j.K("bool_key").Bool(false))
	println(j.K("map").K("key1").String(""))
	println(j.K("map").K("arr").I(0).Int(0))
	println(j.K("map").K("map").K("key1").String(""))
	println(j.K("arr").I(0).K("key1").String(""))
	println(j.K("unexisted_key").String("default"))
}

func TestJSONAll(t *testing.T) {
	data := `{
		"str_key": "hello",
		"int_key": 2333,
		"float_key": 23.33,
		"bool_key": true,
		"map": {
			"key1": "val1",
			"key2": "val2",
			"arr": [1, 2, 3, 4, 5, 6],
			"map": {
				"key1": "val1",
				"key2": "val2"
			}
		},
		"arr": [
			{
				"key1": "key1"
			},
			{
				"key2": "key2"
			}]
	}`

	var j JSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		t.Fatal(err)
	}

	if j.K("str_key").String("") != "hello" {
		t.Fatalf("")
	}
	if j.K("int_key").Int(0) != 2333 {
		t.Fatalf("")
	}
	if j.K("float_key").Float(0) != 23.33 {
		t.Fatalf("")
	}
	if j.K("bool_key").Bool(false) != true {
		t.Fatalf("")
	}
	if j.K("map").K("key1").String("") != "val1" {
		t.Fatalf("")
	}
	if j.K("map").K("arr").I(0).Int(0) != 1 {
		t.Fatalf("")
	}
	if j.K("map").K("map").K("key1").String("") != "val1" {
		t.Fatalf("")
	}
	if j.K("arr").I(0).K("key1").String("") != "key1" {
		t.Fatalf("")
	}
}

func TestJSONArr(t *testing.T) {
	data := `[1, 2, "ok", 4, 5]`
	var j JSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		t.Fatal(err)
	}

	if j.I(0).Int(0) != 1 {
		t.Fatalf("1")
	}

	if j.I(2).String("") != "ok" {
		t.Fatalf("ok")
	}
}

func TestJSONMap(t *testing.T) {
	data := `{
		"key0": {
		"key1": {
		"string": "hello",
		"int": 2333,
		"float": 23.33,
		"bool": true
	}
	}
}`
	var j JSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		t.Fatal(err)
	}
	if j.K("key0").K("key1").K("int").Int(0) != 2333 {
		t.Fatalf("2333")
	}
	if j.K("key0").K("key1").K("string").String("") != "hello" {
		t.Fatalf("2333")
	}
	if !(j.K("key0").K("key1").K("float").Float(0) < 23.33+0.01 &&
		j.K("key0").K("key1").K("float").Float(0) > 23.33-0.01 ) {
		t.Fatalf("23.33")
	}
	if j.K("key0").K("key1").K("bool").Bool(false) != true {
		t.Fatalf("2333")
	}
}

func TestJSONVal(t *testing.T) {
	str := `"key"`
	var j JSON
	if err := json.Unmarshal([]byte(str), &j); err != nil {
		t.Fatal(err)
	}
	if j.String("") != "key" {
		t.Fatalf("")
	}

	number := "2333"
	if err := json.Unmarshal([]byte(number), &j); err != nil {
		t.Fatal(err)
	}
	if j.Int(0) != 2333 {
		t.Fatalf("")
	}

	boolean := "true"
	if err := json.Unmarshal([]byte(boolean), &j); err != nil {
		t.Fatal(err)
	}
	if j.Bool(false) != true {
		t.Fatalf("")
	}
}

func TestJSONNone(t *testing.T) {
	data := `{
		"key0": {
		"key1": {
		"string": "hello",
		"int": 2333,
		"float": 23.33,
		"bool": true
	}
	}
}`
	var j JSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		t.Fatal(err)
	}
	if j.K("none").Int(233) != 233 {
		t.Fatalf("")
	}
	if j.K("none").Float(45.67) != 45.67 {
		t.Fatalf("")
	}
}