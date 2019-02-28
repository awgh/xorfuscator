package xorfuscator

import (
	"bytes"
	"testing"

	"github.com/awgh/bencrypt/bc"
)

func Test_RoundTrip_1(t *testing.T) {

	for i := 1; i < 10; i++ {
		payload, err := bc.GenerateRandomBytes(32)
		if err != nil {
			t.Fatal(err)
		}

		xored, err := XORFuscate(i, payload)
		if err != nil {
			t.Fatal(err)
		}

		dexored, err := DeXORFuscate(i, xored)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("\n%x \n== \n%x\n", payload, dexored)

		if bytes.Compare(payload, dexored) != 0 {
			t.Fatal("Descrambled data did not match original data")
		}
	}
}
