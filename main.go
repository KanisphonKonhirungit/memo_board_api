package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("a8s9d7fG!H2%kL7#xQ3@bF1z+M8nDs0m9p")

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type Memo struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, world!")
	})

	r.HandleFunc("/auth/login", LoginHandler).Methods("POST")
	r.HandleFunc("/home", HomeHandler).Methods("GET")
	r.HandleFunc("/user/{username}", getUserInfoHandler).Methods("GET")
	r.HandleFunc("/memo", CreateMemoHandler).Methods("POST")
	r.HandleFunc("/memos", GetMemosHandler).Methods("GET")

	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"}, // Frontend URL
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}).Handler(r)

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := checkUserFromDB(creds.Username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
		log.Println("Password mismatch", creds.Username, user, err)
		http.Error(w, "Invalid credentials ", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: creds.Username,
		Role:     user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("Invalid token")
	}

	return claims, nil
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	tokenStr = tokenStr[len("Bearer "):]
	claims, err := ValidateToken(tokenStr)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"username": claims.Username, "role": claims.Role})
}

func connectDB() *sql.DB {
	connStr := "user=postgres password=1234 dbname=memo_board host=localhost port=5433 sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func checkUserFromDB(username string) (User, error) {
	var user User
	db := connectDB()
	defer db.Close()

	err := db.QueryRow("SELECT username, email, password FROM users WHERE username=$1", username).Scan(&user.Username, &user.Email, &user.Password)
	if err != nil {
		return user, err
	}
	return user, nil
}

func getUserFromDB(username string) (User, error) {
	var user User
	db := connectDB()
	defer db.Close()

	err := db.QueryRow("SELECT username, email, role FROM users WHERE username=$1", username).Scan(&user.Username, &user.Email, &user.Role)
	if err != nil {
		return user, err
	}
	return user, nil
}

func generateUniqueID(db *sql.DB, role string) (string, error) {
	var id int
	err := db.QueryRow("SELECT nextval('memo_id_seq')").Scan(&id)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%d", role, id), nil
}

func CreateMemoHandler(w http.ResponseWriter, r *http.Request) {
	var memo Memo
	err := json.NewDecoder(r.Body).Decode(&memo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	tokenStr = tokenStr[len("Bearer "):]
	claims, err := ValidateToken(tokenStr)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	db := connectDB()
	defer db.Close()

	memo.Username = claims.Username

	user, err := getUserFromDB(claims.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	memo.Role = user.Role

	if claims.Role == "ADMIN" {
		memo.ID, err = generateUniqueID(db, user.Role)
		if err != nil {
			http.Error(w, "Error generating memo ID", http.StatusInternalServerError)
			return
		}
	} else {
		memo.ID, err = generateUniqueID(db, user.Role)
		if err != nil {
			http.Error(w, "Error generating memo ID", http.StatusInternalServerError)
			return
		}
	}

	memo.CreatedAt = time.Now()
	err = addMemoToDB(memo)
	if err != nil {
		http.Error(w, "Error adding memo", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(memo)
}

func addMemoToDB(memo Memo) error {
	db := connectDB()
	defer db.Close()

	_, err := db.Exec("INSERT INTO memos (id, username, content, created_at, role) VALUES ($1, $2, $3, $4, $5)",
		memo.ID, memo.Username, memo.Content, memo.CreatedAt, memo.Role)
	if err != nil {
		return err
	}

	return nil
}

func GetMemosHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	tokenStr = tokenStr[len("Bearer "):]
	claims, err := ValidateToken(tokenStr)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	user, err := getUserFromDB(claims.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	db := connectDB()
	defer db.Close()

	var rows *sql.Rows

	rows, err = db.Query("SELECT id, username, content, created_at, role FROM memos ORDER BY created_at DESC")
	if user.Role == "USER" {
		rows, err = db.Query("SELECT id, username, content, created_at, role FROM memos WHERE username=$1 ORDER BY created_at ASC", claims.Username)
	}

	if err != nil {
		http.Error(w, "Error fetching memos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var memos []Memo
	for rows.Next() {
		var memo Memo
		err := rows.Scan(&memo.ID, &memo.Username, &memo.Content, &memo.CreatedAt, &memo.Role)
		if err != nil {
			http.Error(w, "Error scanning memos", http.StatusInternalServerError)
			return
		}
		memos = append(memos, memo)
	}

	if len(memos) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(memos)
}

func getUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	user, err := getUserFromDB(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
