package embargo_test

import (
	"encoding/json"
	"fmt"

	"github.com/nao1215/embargo"
)

func ExampleNewSecret() {
	key := embargo.NewSecret("fake-key")

	fmt.Println(key)

	// Output: [REDACTED]
}

func ExampleSecret() {
	var empty embargo.Secret[string]

	fmt.Println(empty, empty.Reveal() == "")

	// Output: [REDACTED] true
}

func ExampleSecret_Reveal() {
	key := embargo.NewSecret("fake-key")

	fmt.Println(len(key.Reveal()))

	// Output: 8
}

func ExampleInput() {
	var input embargo.Input[string]
	if err := input.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Println(input)

	// Output: [REDACTED]
}

func ExampleInput_UnmarshalJSON() {
	var config struct {
		Token embargo.Input[string] `json:"token"`
	}
	if err := json.Unmarshal([]byte(`{"token":"fake-key"}`), &config); err != nil {
		panic(err)
	}

	fmt.Println(config.Token.Secret())

	// Output: [REDACTED]
}

func ExampleInput_UnmarshalJSON_failure() {
	var config struct {
		First  embargo.Input[string] `json:"first"`
		Second embargo.Input[string] `json:"second"`
	}
	if err := json.Unmarshal([]byte(`{"first":"fake-key","second":"[REDACTED]"}`), &config); err != nil {
		fmt.Println("configuration rejected")
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

	fmt.Println(input.Secret())

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

	fmt.Println(len(snapshot.Reveal()))

	// Output: 5
}

func ExampleSecret_String() {
	value := embargo.NewSecret("fake-key")

	fmt.Println(value.String())

	// Output: [REDACTED]
}

func ExampleSecret_GoString() {
	value := embargo.NewSecret("fake-key")

	fmt.Println(value.GoString())

	// Output: [REDACTED]
}

func ExampleSecret_Format() {
	value := embargo.NewSecret("fake-key")

	fmt.Printf("%+#v\n", value)

	// Output: [REDACTED]
}

func ExampleSecret_LogValue() {
	value := embargo.NewSecret("fake-key")

	fmt.Println(value.LogValue().String())

	// Output: [REDACTED]
}

func ExampleSecret_MarshalJSON() {
	value := embargo.NewSecret("fake-key")
	data, err := value.MarshalJSON()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

	// Output: "[REDACTED]"
}

func ExampleSecret_MarshalText() {
	value := embargo.NewSecret("fake-key")
	data, err := value.MarshalText()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

	// Output: [REDACTED]
}

func ExampleInput_String() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Println(value.String())

	// Output: [REDACTED]
}

func ExampleInput_GoString() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Println(value.GoString())

	// Output: [REDACTED]
}

func ExampleInput_Format() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Printf("%+#v\n", value)

	// Output: [REDACTED]
}

func ExampleInput_LogValue() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Println(value.LogValue().String())

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

	fmt.Println(string(data))

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

	fmt.Println(string(data))

	// Output: [REDACTED]
}
