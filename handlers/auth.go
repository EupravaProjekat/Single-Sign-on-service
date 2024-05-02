package handlers

import (
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"strings"

	protos "github.com/MihajloJankovic/Auth-Service/protos/main"
)

type MyAuthServer struct {
	logger *log.Logger
	// NoSQL: injecting product repository
	repo *AuthRepo
}

func NewServer(l *log.Logger, r *AuthRepo) *MyAuthServer {
	return &MyAuthServer{l, r}
}

// isValidEmailFormat checks if the given email is in a valid format.
func isValidEmailFormat(email string) bool {
	// Perform a simple check for '@' and '.com'
	return strings.Contains(email, "@") && strings.HasSuffix(email, ".com")
}

// trimSpace trims leading and trailing whitespaces from a string.
func trimSpace(s string) string {
	return strings.TrimSpace(s)
}

var passwordBlacklist map[string]struct{}

func init() {
	// Initialize the password blacklist set
	loadPasswordBlacklist()
}

func loadPasswordBlacklist() {
	blacklistData, err := ioutil.ReadFile("/root/password-blacklist.txt")
	if err != nil {
		log.Println("Error reading blacklist file:", err)
		return
	}

	passwordBlacklist = make(map[string]struct{})
	blacklistLines := strings.Split(string(blacklistData), "\n")

	for _, line := range blacklistLines {
		passwordBlacklist[strings.TrimSpace(line)] = struct{}{}
	}
}

func isPasswordInBlacklist(password string) bool {
	_, exists := passwordBlacklist[password]
	return exists
}
func (s *MyAuthServer) Register(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	mediatype, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if mediatype != "application/json" {
		err := errors.New("expect application/json Content-Type")
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}

	rt, err := DecodeBodyAuthLog(r.Body)
	if err != nil {
		err := errors.New("data error")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Trim leading and trailing whitespaces from email and password
	email := trimSpace(rt.GetEmail())
	password := trimSpace(rt.GetPassword())

	if email == "" || password == "" {
		err := errors.New("empty fields")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	// Check if it's a valid email format
	if !isValidEmailFormat(email) {
		err := errors.New("email is not in valid format")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	if isPasswordInBlacklist(password) {
		err := errors.New("Password on blacklist!")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	out := new(protos.AuthResponse)
	out.Email = rt.Email
	out.Password = rt.Password
	out.Ticket = RandomString(18)
	out.Activated = false
	out.TicketReset = RandomString(24)
	err = s.repo.Create(out)
	if err != nil {
		s.logger.Println(err)
		err := errors.New("error in creation")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Send activation link to the user via email
	activationLink := fmt.Sprintf("http://localhost:9094/activate/%s/%s", out.Email, out.Ticket)

	if err := sendActivationEmail(out.Email, activationLink); err != nil {
		s.logger.Println("Failed to send activation email:", err)
		// You can choose to return an error or handle it as appropriate for your application
	}
	w.WriteHeader(http.StatusCreated)
	return
}
func (s *MyAuthServer) Login(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	mediatype, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if mediatype != "application/json" {
		err := errors.New("expect application/json Content-Type")
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	rt, err := DecodeBodyAuthLog(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusAccepted)
		return
	}

	// Trim leading and trailing whitespaces from email and password
	email := trimSpace(rt.GetEmail())
	password := trimSpace(rt.GetPassword())

	if email == "" || password == "" {
		err := errors.New("empty fields")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	// Check if it's a valid email format
	if !isValidEmailFormat(email) {
		err := errors.New("email is not in valid format")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	err = s.repo.Login(rt.Email, rt.Password)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("Login failed"))
		if err != nil {
			return
		}
		return
	}
	jwt := GenerateJwt(w, rt.GetEmail())
	w.WriteHeader(http.StatusOK)
	// adds token to request header
	RenderJSON(w, jwt)
}

func (s *MyAuthServer) GetTicket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]
	res := ValidateJwt(r, s.repo)
	if res == nil {
		err := errors.New("jwt error")
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	re := res
	if re.GetEmail() != email {
		err := errors.New("authorization error")
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	response, err := s.repo.GetTicketByEmail(email)
	if err != nil {
		log.Println("Failed to get ticket ", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed to get ticket"))
		return
	}

	w.WriteHeader(http.StatusOK)
	RenderJSON(w, &protos.AuthTicket{Ticket: response.Ticket})
}

func (s *MyAuthServer) Activate(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	email := params["email"]
	ticket := params["ticket"]

	_, err := s.repo.Activate(email, ticket)
	if err != nil {
		log.Println("Failed to activate account", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed to activate account"))
		return
	}

	w.WriteHeader(http.StatusOK)
	RenderJSON(w, "Activated account")

}

func (s *MyAuthServer) ChangePassword(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	mediatype, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if mediatype != "application/json" {
		err := errors.New("expect application/json Content-Type")
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	rt, err := DecodeBodyPassword(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusAccepted)
		return
	}
	res := ValidateJwt(r, s.repo)
	if res == nil {
		err := errors.New("jwt error")
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	re := res
	if re.GetEmail() != rt.Email {
		err := errors.New("authorization error")
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	out := new(protos.ChangePasswordRequest)
	out.Email = rt.Email
	out.CurrentPassword = rt.CurrentPassword
	out.NewPassword = rt.NewPassword
	// Validate email, currentPassword, and newPassword here
	if out.GetEmail() == "" || out.GetCurrentPassword() == "" || out.GetNewPassword() == "" {
		s.logger.Println(err)
		err := errors.New("Invalid input. Email, current password, and new password are required.")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	currentAuth, err := s.repo.GetByEmail(out.GetEmail())

	if isPasswordInBlacklist(out.GetNewPassword()) {
		s.logger.Println(err)
		err := errors.New("New password blacklisted!")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Check if the provided current password matches the stored password
	if err := bcrypt.CompareHashAndPassword([]byte(currentAuth.GetPassword()), []byte(out.GetCurrentPassword())); err != nil {
		s.logger.Println(err)
		err := errors.New("current password is incorrect")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Generate and set the new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(out.GetNewPassword()), 14)
	if err != nil {
		s.logger.Println(err)
		err := errors.New("error with encryption")
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	currentAuth.Password = string(newPasswordHash)

	err = s.repo.ChangePasswordByEmail(out.Email, out.CurrentPassword, currentAuth.Password)
	if err != nil {
		log.Println("Failure in password changing!", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failure in password changing!"))
		return
	}

	w.WriteHeader(http.StatusAccepted)
	RenderJSON(w, "Password changed successfully!")

}

func (s *MyAuthServer) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	mediatype, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if mediatype != "application/json" {
		err := errors.New("expect application/json Content-Type")
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	rt, err := DecodeBodyAuth(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusAccepted)
		return
	}

	// Generate a new random string for ticketReset and store it in the database
	newTicketReset := RandomString(24)
	if err := s.repo.UpdateResetTicket(rt.Email, newTicketReset); err != nil {
		log.Println("Failed to request password reset", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed to request password reset"))
		return
	}

	// Send the reset link to the user via email
	resetLink := fmt.Sprintf("http://localhost:4200/reset/%s/%s", rt.Email, newTicketReset)

	if err := sendResetLinkEmail(rt.Email, resetLink); err != nil {
		s.logger.Println("Failed to send reset email:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed to request password reset"))
		return
	}

	w.WriteHeader(http.StatusOK)
	RenderJSON(w, "Password reset requested successfully")
}

//func (s *MyAuthServer) DeleteHost(w http.ResponseWriter, r *http.Request) {
//	email := mux.Vars(r)["email"]
//	user, err := s.hh.GetProfileInner(email)
//	if err != nil {
//		log.Printf("RPC failed: %v\n", err)
//		w.WriteHeader(http.StatusInternalServerError)
//		_, _ = w.Write([]byte("Couldn't delete host"))
//
//		return
//	}
//	if user.GetRole() != "Host" {
//		w.WriteHeader(http.StatusInternalServerError)
//		_, _ = w.Write([]byte("You are not a host"))
//
//		return
//	}
//	res := ValidateJwt(r, s.hh)
//	if res == nil {
//		err := errors.New("jwt error")
//		http.Error(w, err.Error(), http.StatusForbidden)
//		return
//	}
//	re := res
//	if re.GetEmail() != email {
//		err := errors.New("authorization error")
//		http.Error(w, err.Error(), http.StatusForbidden)
//		return
//	}
//	temp := new(protosAuth.AuthGet)
//	temp.Email = email
//	_, err = s.cc.DeleteHost(context.Background(), temp)
//	if err != nil {
//		log.Printf("RPC failed: %v\n", err)
//		w.WriteHeader(http.StatusInternalServerError)
//		_, err := w.Write([]byte("Couldn't delete account"))
//		if err != nil {
//			return
//		}
//		return
//	}
//
//	w.WriteHeader(http.StatusOK)
//	RenderJSON(w, "Account deleted successfully")
//}
//func (s *MyAuthServer) DeleteAccount(w http.ResponseWriter, r *http.Request) {
//	email := mux.Vars(r)["email"]
//	user, err := s.hh.GetProfileInner(email)
//	if err != nil {
//		log.Printf("RPC failed: %v\n", err)
//		w.WriteHeader(http.StatusInternalServerError)
//		_, _ = w.Write([]byte("Couldn't delete guest"))
//
//		return
//	}
//	if user.GetRole() != "Guest" {
//		w.WriteHeader(http.StatusInternalServerError)
//		_, _ = w.Write([]byte("You are not a guest"))
//
//		return
//	}
//	res := ValidateJwt(r, s.hh)
//	if res == nil {
//		err := errors.New("jwt error")
//		http.Error(w, err.Error(), http.StatusForbidden)
//		return
//	}
//	re := res
//	if re.GetEmail() != email {
//		err := errors.New("authorization error")
//		http.Error(w, err.Error(), http.StatusForbidden)
//		return
//	}
//
//	temp := new(protosAuth.AuthGet)
//	temp.Email = email
//	_, err = s.cc.DeleteGuest(context.Background(), temp)
//	if err != nil {
//		log.Printf("RPC failed: %v\n", err)
//		w.WriteHeader(http.StatusInternalServerError)
//		_, err := w.Write([]byte("Couldn't delete account"))
//		if err != nil {
//			return
//		}
//		return
//	}
//
//	w.WriteHeader(http.StatusOK)
//	RenderJSON(w, "Account deleted successfully")
//}
