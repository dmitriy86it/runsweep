package model

import (
	"encoding/json"
	"testing"
)

func TestStatusOrderAndJSON(t *testing.T) {
	if Worse(Possible, Affected) != Affected || Worse(Unchecked, Clean) != Unchecked {
		t.Fatal("Worse must return the more severe status")
	}
	b, err := json.Marshal(struct{ S Status }{Affected})
	if err != nil || string(b) != `{"S":"AFFECTED"}` {
		t.Fatalf("got %s, %v", b, err)
	}
	if Possible.String() != "POSSIBLE" {
		t.Fatal(Possible.String())
	}
}
