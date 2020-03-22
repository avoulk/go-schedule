package middleware

import (
	"context"
	"net/http"
	"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	logging "github.com/golang/glog"

	models "github.com/avoulk/go-schedule/models"
	utils "github.com/avoulk/go-schedule/utils"
)

//JwtAuthentication checks whether there is a token in a request header
//and validates it.
var JwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		notAuth := []string{"/api/user/new", "/api/user/login"} //List of endpoints that doesn't require auth
		requestPath := r.URL.Path                               //current request path

		//check if request does not need authentication, serve the request if it doesn't need it
		for _, value := range notAuth {

			if value == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		response := make(map[string]interface{})
		tokenHeader := r.Header.Get("Authorization") //Grab the token from the header

		if tokenHeader == "" { //Token is missing, returns with error code 403 Unauthorized
			response = utils.Message(false, "Missing auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w, response)
			return
		}

		splitted := strings.Split(tokenHeader, " ") //The token normally comes in format `Bearer {token-body}`, we check if the retrieved token matched this requirement
		if len(splitted) != 2 {
			response = utils.Message(false, "Invalid/Malformed auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w, response)
			logging.Warningln("Invalid auth token: %v", response)
			return
		}

		tokenPart := splitted[1] //Grab the token part, what we are truly interested in
		tk := &models.Token{}

		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("token_password")), nil
		})

		if err != nil { //Malformed token, returns with http code 403 as usual
			response = utils.Message(false, "Malformed authentication token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w, response)
			logging.Warning("Invalid auth token: %v", response)
			return
		}

		if !token.Valid { //Token is invalid, maybe not signed on this server
			response = utils.Message(false, "Token is not valid.")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			utils.Respond(w, response)
			return
		}

		//Everything went well, proceed with the request and set the caller to the user retrieved from the parsed token
		ctx := context.WithValue(r.Context(), "username", tk.Username)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r) //proceed in the middleware chain!
	})
}

//CheckPwd checks a given password for its strength and returns whether it is safe and
//what is the message we got from the text
func CheckPwd(password string) (Safe bool, Message string) {
	checker := pwdbro.newDefaultPwdBro()
	status, err = checker.RunParallelChecks(password)
	for _, resp := range status {
		Safe = resp.Safe
		Message = resp.Message
	}
	return
}
