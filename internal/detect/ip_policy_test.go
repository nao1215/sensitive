package detect

import "testing"

func TestIPLocalAddressesAreNotPrivateEndpoints(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"0.0.0.0", "::", "127.0.0.1", "127.255.255.254", "::1"} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			if got := NewIPAddr().Scan([]byte("listener [" + address + "]")); len(got) != 0 {
				t.Fatal("host-independent address must not identify a private endpoint")
			}
		})
	}
	for _, address := range []string{"10.0.0.1", "126.255.255.255", "128.0.0.1", "192.0.2.1", "2001:db8::1"} {
		if got := NewIPAddr().Scan([]byte(address)); len(got) != 1 || got[0].Start != 0 || got[0].End != len(address) {
			t.Fatal("endpoint protection changed")
		}
	}
}
