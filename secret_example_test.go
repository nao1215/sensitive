package embargo_test

import (
	"encoding/json"
	"fmt"

	"github.com/nao1215/embargo"
)

func ExampleNewSecret() {
	key := embargo.NewSecret("fake-key")
	if _, err := fmt.Println(key); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleSecret() {
	var empty embargo.Secret[string]
	if _, err := fmt.Println(empty, empty.Reveal() == ""); err != nil {
		panic(err)
	}

	// Output: [REDACTED] true
}

func ExampleSecret_Reveal() {
	key := embargo.NewSecret("fake-key")
	if _, err := fmt.Println(len(key.Reveal())); err != nil {
		panic(err)
	}

	// Output: 8
}

func ExampleInput() {
	var input embargo.Input[string]
	if err := input.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	if _, err := fmt.Println(input); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleInput_UnmarshalJSON() {
	var config struct {
		Token embargo.Input[string] `json:"token"`
	}
	if err := json.Unmarshal([]byte(`{"token":"fake-key"}`), &config); err != nil {
		panic(err)
	}
	if _, err := fmt.Println(config.Token.Secret()); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleInput_UnmarshalJSON_failure() {
	var config struct {
		First  embargo.Input[string] `json:"first"`
		Second embargo.Input[string] `json:"second"`
	}
	if err := json.Unmarshal([]byte(`{"first":"fake-key","second":"[REDACTED]"}`), &config); err != nil {
		if _, printErr := fmt.Println("configuration rejected"); printErr != nil {
			panic(printErr)
		}
		return // Discard the whole partially decoded config.
	}
	panic("unexpected successful decode")

	// Output: configuration rejected
}

func ExampleInput_UnmarshalText() {
	var input embargo.Input[[]byte]
	if err := input.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	if _, err := fmt.Println(input.Secret()); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleInput_Secret() {
	var input embargo.Input[string]
	if err := input.UnmarshalText([]byte("first")); err != nil {
		panic(err)
	}
	snapshot := input.Secret()
	if err := input.UnmarshalText([]byte("second")); err != nil {
		panic(err)
	}
	if _, err := fmt.Println(len(snapshot.Reveal())); err != nil {
		panic(err)
	}

	// Output: 5
}

func ExampleSecret_String() {
	value := embargo.NewSecret("fake-key")
	if _, err := fmt.Println(value.String()); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleSecret_GoString() {
	value := embargo.NewSecret("fake-key")
	if _, err := fmt.Println(value.GoString()); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleSecret_Format() {
	value := embargo.NewSecret("fake-key")
	if _, err := fmt.Printf("%+#v\n", value); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleSecret_LogValue() {
	value := embargo.NewSecret("fake-key")
	if _, err := fmt.Println(value.LogValue().String()); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleSecret_MarshalJSON() {
	value := embargo.NewSecret("fake-key")
	data, err := value.MarshalJSON()
	if err != nil {
		panic(err)
	}
	if _, err := fmt.Println(string(data)); err != nil {
		panic(err)
	}

	// Output: "[REDACTED]"
}

func ExampleSecret_MarshalText() {
	value := embargo.NewSecret("fake-key")
	data, err := value.MarshalText()
	if err != nil {
		panic(err)
	}
	if _, err := fmt.Println(string(data)); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleInput_String() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	if _, err := fmt.Println(value.String()); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleInput_GoString() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	if _, err := fmt.Println(value.GoString()); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleInput_Format() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	if _, err := fmt.Printf("%+#v\n", value); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleInput_LogValue() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	if _, err := fmt.Println(value.LogValue().String()); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}

func ExampleInput_MarshalJSON() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	data, err := value.MarshalJSON()
	if err != nil {
		panic(err)
	}
	if _, err := fmt.Println(string(data)); err != nil {
		panic(err)
	}

	// Output: "[REDACTED]"
}

func ExampleInput_MarshalText() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	data, err := value.MarshalText()
	if err != nil {
		panic(err)
	}
	if _, err := fmt.Println(string(data)); err != nil {
		panic(err)
	}

	// Output: [REDACTED]
}
