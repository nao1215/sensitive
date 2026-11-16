package embargo_test

import (
	"context"
	"fmt"

	"github.com/nao1215/embargo"
)

func ExampleScanner_MaskJSON() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	// Sanitize an audit export before uploading it to a support system.
	safe, err := scanner.MaskJSON([]byte(`{"user":{"email":"alice@example.com","password":"opaque"},"amount":125,"paid":true}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(safe))
	// Output:
	// {"user":{"email":"[REDACTED]","password":"[REDACTED]"},"amount":125,"paid":true}
}

func ExampleWithSensitiveKeys() {
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithSensitiveKeys("password", "passwd", "secret", "token", "api_key", "authorization", "cookie", "set-cookie", "recovery_code"))
	safe, err := scanner.MaskJSON([]byte(`{"recoveryCode":"opaque","api-key":"opaque","count":3}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(safe))
	// Output:
	// {"recoveryCode":"[REDACTED]","api-key":"[REDACTED]","count":3}
}

func ExampleInput_Scan() {
	var password embargo.Input[string]
	// rows.Scan(&password) calls the same method with the driver's string or bytes.
	if err := password.Scan([]byte("synthetic-database-password")); err != nil {
		panic(err)
	}
	secret := password.Secret()
	fmt.Println(secret)
	fmt.Println(secret.Reveal() == "synthetic-database-password")
	// Output:
	// [REDACTED]
	// true
}

func ExampleScanner_MaskJSONContext() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	safe, err := embargo.NewScanner().MaskJSONContext(ctx, []byte(`{"email":"alice@example.com"}`))
	fmt.Println(len(safe), err != nil)
	// Output: 0 true
}
