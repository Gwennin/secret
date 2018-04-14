package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"

	"github.com/Gwennin/secret/store"
)

var s *store.Store

func main() {
	var err error
	s, err = store.NewStore()
	if err != nil {
		panic(err)
	}

	defer s.Close()

	r := mux.NewRouter()
	r.HandleFunc("/api", Save).Methods("POST")
	r.HandleFunc("/api/{id:[0-9a-fA-F]{64}}", Get).Methods("GET")

	n := negroni.Classic()
	n.UseHandler(r)
	n.Run(":3000")
}

func Get(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	data, err := s.Get(id)
	if err != nil {
		log.Printf("Unable to get id %q: %v", id, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if data == nil {
		log.Printf("id %q not found", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	expired := data.Expiration.Before(time.Now().UTC())
	d := struct {
		Text       string `json:",omitempty"`
		Expired    bool
		Expiration *time.Time `json:",omitempty"`
	}{
		Expired: expired,
	}

	if expired {
		d.Text = data.Text
	} else {
		d.Expiration = &data.Expiration
	}

	payload, err := json.Marshal(d)
	if err != nil {
		log.Printf("Unable to marshal id %q: %v", id, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}

func Save(w http.ResponseWriter, r *http.Request) {
	type data struct {
		Text       string
		Expiration time.Time
	}

	decoder := json.NewDecoder(r.Body)
	var d data
	err := decoder.Decode(&d)
	if err != nil {
		log.Printf("Unable to unmarshal: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	if len(d.Text) == 0 || d.Expiration.Before(time.Now().UTC()) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Text and expiration date must be set")
		return
	}

	id, err := s.Save(d.Text, d.Expiration)
	if err != nil {
		log.Printf("Unable to save: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(id))
}
