package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	protosAuth "github.com/MihajloJankovic/Auth-Service/protos/main"
	protosava "github.com/MihajloJankovic/Aviability-Service/protos/main"
	protosAcc "github.com/MihajloJankovic/accommodation-service/protos/main"
	protos "github.com/MihajloJankovic/profile-service/protos/main"
	protosRes "github.com/MihajloJankovic/reservation-service/protos/genfiles"
	"github.com/golang-jwt/jwt/v5"
)

func StreamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(stream)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}
func GenerateJwt(w http.ResponseWriter, email string) string {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	ttl := 600 * time.Second
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["isu"] = jwt.NewNumericDate(time.Now())
	claims["email"] = email
	claims["exp"] = time.Now().UTC().Add(ttl).Unix()
	var sampleSecretKey = []byte("SecretYouShouldHide")
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(sampleSecretKey)
	if err != nil {
		fmt.Println(err)
	}
	return tokenString
}
func DecodeBody(r io.Reader) (*protos.ProfileResponse, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protos.ProfileResponse
	if err := json.Unmarshal(StreamToByte(r), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

func DecodeBodyAva(r io.Reader) (*protosava.CheckSet, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosava.CheckSet
	if err := json.Unmarshal(StreamToByte(r), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}
func DecodeBodyAva4(r io.Reader) (*protosRes.ReservationRequest, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosRes.ReservationRequest
	if err := json.Unmarshal(StreamToByte(r), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}
func DecodeBodyAva3(r io.Reader) (*protosava.GetAllRequest, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosava.GetAllRequest
	if err := json.Unmarshal(StreamToByte(r), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}
func DecodeBodyAva2(r io.Reader) (*protosava.CheckRequest, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosava.CheckRequest
	if err := json.Unmarshal(StreamToByte(r), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}
func DecodeBodyPorfileadd(string2 string) (*protos.ProfileResponse, error) {

	var rt protos.ProfileResponse
	if err := json.Unmarshal([]byte(string2), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}
func DecodeBodyAcc(r io.Reader) (*protosAcc.AccommodationResponse, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosAcc.AccommodationResponse
	if err := json.Unmarshal(StreamToByte(r), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

func DecodeBodyRes(r io.Reader) (*protosRes.ReservationResponse, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosRes.ReservationResponse
	if err := json.Unmarshal(StreamToByte(r), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

type RequestRegister struct {
	Email     string
	Firstname string
	Lastname  string
	Birthday  string
	Gender    string
	Role      string
	Password  string
	Username  string
}

func DecodeBodyRes2(r io.Reader) (*protosRes.Emaill, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosRes.Emaill
	if err := json.Unmarshal(StreamToByte(r), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}
func DecodeBodyAuth(r io.Reader) (*RequestRegister, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt RequestRegister
	if err := json.Unmarshal(StreamToByte(r), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

func DecodeBodyPassword(r io.Reader) (*protosAuth.ChangePasswordRequest, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosAuth.ChangePasswordRequest
	if err := json.NewDecoder(r).Decode(&rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

func DecodeBodyAuthLog(r io.Reader) (*protosAuth.AuthRequest, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosAuth.AuthRequest
	if err := json.NewDecoder(r).Decode(&rt); err != nil {
		return nil, err
	}
	return &rt, nil
}
func ToJSON(response *protos.ProfileResponse) (string, error) {
	jsonData, err := json.Marshal(response)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return "", err
	}
	return string(jsonData), nil
}
func RenderJSON(w http.ResponseWriter, v interface{}) {
	js, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(js)
	if err != nil {
		return
	}
}
func ValidateJwt(r *http.Request, h *AuthRepo) *protosAuth.AuthResponse {
	tokenString := r.Header.Get("jwt")
	if tokenString == "" {
		return nil
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte("SecretYouShouldHide"), nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok == false || token.Valid == false {
		return nil

	}
	exp := claims["exp"].(float64)
	email := claims["email"].(string)
	if float64(time.Now().UTC().Unix()) > exp {
		return nil
	}
	rt, err := h.GetByEmail(email)
	if err != nil {
		return nil
	}
	return rt
}
func DecodeBodyReset(r io.Reader) (*protosAuth.ResetRequest, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosAuth.ResetRequest
	if err := dec.Decode(&rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

func getTodaysDateInLocal() string {
	// Get the current time in the local timezone
	currentTime := time.Now().Local()

	// Format the date as yyyy-mm-dd
	formattedDate := currentTime.Format("2006-01-02")

	return formattedDate
}

func DecodeBodyPriceAndId(r io.Reader) (*protosava.PriceAndIdRequest, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt protosava.PriceAndIdRequest
	if err := dec.Decode(&rt); err != nil {
		return nil, err
	}
	return &rt, nil
}
