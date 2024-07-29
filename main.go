package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from %s!", os.Getenv("SERVICE_NAME"))
}

func main() {
	url := os.Getenv("TARGET_URL")
	if url == "" {
		log.Fatal("TARGET_URL environment variable is not set")
	}

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable is not set")
	}

	http.HandleFunc("/", handler)
	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
	}()

	for {
		resp, err := http.Get(url)
		if err != nil {
			log.Println("Error:", err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			log.Println("Response:", string(body))
			resp.Body.Close()
		}
		time.Sleep(5 * time.Second)
	}
}
