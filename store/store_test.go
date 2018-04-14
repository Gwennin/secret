package store_test

import (
	"testing"
	"time"

	"github.com/Gwennin/secret/store"
)

func TestSave(t *testing.T) {
	s, err := store.NewStore()
	if err != nil {
		t.Fatal("NewStore shall not fail", err)
	}

	_, err = s.Save("This is for testing", time.Now().UTC())
	if err != nil {
		t.Fatal("Save shall not fail", err)
	}
}

func TestGet(t *testing.T) {
	s, err := store.NewStore()
	if err != nil {
		t.Fatal("NewStore shall not fail", err)
	}

	//s.Save("Text 1", time.Now().UTC())
	expectedText := "Middle text"
	id, _ := s.Save(expectedText, time.Now().UTC())
	//s.Save("Last inserted text", time.Now().UTC())

	d, err := s.Get(id)
	if err != nil {
		t.Fatal("Get shall not fail", err)
	}

	if d == nil {
		t.Fatal("Get shall return something")
	}

	if d.ID != id {
		t.Fatalf("Get shall return ID %q", id)
	}

	if d.Text != expectedText {
		t.Fatalf("Get shall return %q", expectedText)
	}
}

func TestGetNone(t *testing.T) {
	s, err := store.NewStore()
	if err != nil {
		t.Fatal("NewStore shall not fail", err)
	}

	d, err := s.Get("6ac47e4fa451ef7b00adba2167381090fe3ad4dabbd1b7991cecd9783a5dff7a")
	if err != nil {
		t.Fatal("Get shall not fail", err)
	}

	if d != nil {
		t.Fatal("Get shall return nil")
	}
}
