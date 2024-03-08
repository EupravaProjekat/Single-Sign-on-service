package main

import (
	"context"
	"errors"
	habb "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MihajloJankovic/Auth-Service/handlers"
)

func main() {
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	timeoutContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := log.New(os.Stdout, "[auth-main] ", log.LstdFlags)
	authlog := log.New(os.Stdout, "[auth-repo-log] ", log.LstdFlags)

	authRepo, err := handlers.New(timeoutContext, authlog)
	if err != nil {
		logger.Fatal(err)
	}
	defer authRepo.Disconnect(timeoutContext)

	// NoSQL: Checking if the connection was established
	authRepo.Ping()
	//acc,profile,ava,res

	service := handlers.NewServer(logger, authRepo)

	router := mux.NewRouter()
	router.StrictSlash(true)
	//auth
	router.HandleFunc("/register", service.Register).Methods("POST")
	router.HandleFunc("/login", service.Login).Methods("POST")
	router.HandleFunc("/getTicket/{email}", service.GetTicket).Methods("GET")
	router.HandleFunc("/activate/{email}/{ticket}", service.Activate).Methods("GET")
	router.HandleFunc("/change-password", service.ChangePassword).Methods("POST")
	router.HandleFunc("/request-reset", service.RequestPasswordReset).Methods("POST")
	//router.HandleFunc("/reset", service.reset).Methods("POST")

	headersOk := habb.AllowedHeaders([]string{"Content-Type", "jwt", "Authorization"})
	originsOk := habb.AllowedOrigins([]string{"http://localhost:4200"}) // Replace with your frontend origin
	methodsOk := habb.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})

	// Use the CORS middleware
	corsRouter := habb.CORS(originsOk, headersOk, methodsOk)(router)

	// Start the server
	srv := &http.Server{Addr: ":9094", Handler: corsRouter}
	go func() {
		log.Println("server starting")
		if err := srv.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				log.Fatal(err)
			}
		}
	}()
	<-quit
	log.Println("service shutting down ...")

	// gracefully stop server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
	log.Println("server stopped")
}
