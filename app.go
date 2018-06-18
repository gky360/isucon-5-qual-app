package main

import (
	"database/sql"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	db    *sql.DB
	store *sessions.CookieStore
)

type User struct {
	ID          int
	AccountName string
	NickName    string
	Email       string
}

type Profile struct {
	UserID    int
	FirstName string
	LastName  string
	Sex       string
	Birthday  mysql.NullTime
	Pref      string
	UpdatedAt time.Time
}

type Entry struct {
	ID        int
	UserID    int
	Private   bool
	Title     string
	Content   string
	CreatedAt time.Time
}

type Comment struct {
	ID        int
	EntryID   int
	UserID    int
	Comment   string
	CreatedAt time.Time
}

type Friend struct {
	ID        int
	CreatedAt time.Time
}

type Footprint struct {
	UserID    int
	OwnerID   int
	CreatedAt time.Time
	Updated   time.Time
}

var prefs = []string{"未入力",
	"北海道", "青森県", "岩手県", "宮城県", "秋田県", "山形県", "福島県", "茨城県", "栃木県", "群馬県", "埼玉県", "千葉県", "東京都", "神奈川県", "新潟県", "富山県",
	"石川県", "福井県", "山梨県", "長野県", "岐阜県", "静岡県", "愛知県", "三重県", "滋賀県", "京都府", "大阪府", "兵庫県", "奈良県", "和歌山県", "鳥取県", "島根県",
	"岡山県", "広島県", "山口県", "徳島県", "香川県", "愛媛県", "高知県", "福岡県", "佐賀県", "長崎県", "熊本県", "大分県", "宮崎県", "鹿児島県", "沖縄県"}

var (
	ErrAuthentication   = errors.New("Authentication error.")
	ErrPermissionDenied = errors.New("Permission denied.")
	ErrContentNotFound  = errors.New("Content not found.")
)

type relations map[int]map[int]time.Time
var (
	rels relations
	relsMutex = &sync.Mutex{}
)

func loadRelations() (relations, error) {
	rows, err := db.Query(`SELECT one, another, created_at FROM relations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rs := relations{}
	for rows.Next() {
		var one, another int
		var createdAt time.Time
		if err := rows.Scan(&one, &another, &createdAt); err != nil {
			return nil, err
		}
		if m, ok := rs[one]; ok {
			m[another] = createdAt
		} else {
			rs[one] = map[int]time.Time{another: createdAt}
		}
	}

	return rs, nil
}

func addEdge(a, b int, createdAt time.Time) bool {
	if rels[a] == nil {
		rels[a] = map[int]time.Time{}
	}
	if !rels[a][b].IsZero() {
		return false
	}
	rels[a][b] = createdAt
	return true
}

func createRelationIfNotExists(a, b int) bool {
	createdAt := time.Now()
	relsMutex.Lock()
	defer relsMutex.Unlock()
	ret := addEdge(a, b, createdAt)
	ret = addEdge(b, a, createdAt) || ret
	return ret
}

func getFriendsFromRelations(userID int) []Friend {
	friends := []Friend{}
	if rels[userID] == nil {
		rels[userID] = map[int]time.Time{}
	}
	for anotherID, createdAt := range rels[userID] {
		friends = append(friends, Friend{anotherID, createdAt})
	}
	return friends
}


var (
	id2user map[int]*User
	an2user map[string]*User
)

func loadUsers() error {
	query := `SELECT u.id AS id, u.account_name AS account_name, u.nick_name AS nick_name, u.email AS email
From users u`
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	id2user = map[int]*User{}
	an2user = map[string]*User{}
	for rows.Next() {
		u := User{}
		if err := rows.Scan(&u.ID, &u.AccountName, &u.NickName, &u.Email); err != nil {
			return err
		}
		id2user[u.ID] = &u
		an2user[u.AccountName] = &u
	}

	return nil
}

func authenticate(w http.ResponseWriter, r *http.Request, email, passwd string) {
	query := `SELECT u.id AS id, u.account_name AS account_name, u.nick_name AS nick_name, u.email AS email
FROM users u
JOIN salts s ON u.id = s.user_id
WHERE u.email = ? AND u.passhash = SHA2(CONCAT(?, s.salt), 512)`
	row := db.QueryRow(query, email, passwd)
	user := User{}
	err := row.Scan(&user.ID, &user.AccountName, &user.NickName, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			checkErr(ErrAuthentication)
		}
		checkErr(err)
	}
	session := getSession(w, r)
	session.Values["user_id"] = user.ID
	session.Save(r, w)
}

func getCurrentUser(w http.ResponseWriter, r *http.Request) *User {
	u := context.Get(r, "user")
	if u != nil {
		user := u.(User)
		return &user
	}
	session := getSession(w, r)
	userID, ok := session.Values["user_id"]
	if !ok || userID == nil {
		return nil
	}
	user := id2user[userID.(int)]
	if user == nil {
		checkErr(ErrAuthentication)
	}
	context.Set(r, "user", *user)
	return user
}

func authenticated(w http.ResponseWriter, r *http.Request) bool {
	user := getCurrentUser(w, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return false
	}
	return true
}

func getUser(w http.ResponseWriter, userID int) *User {
	user := id2user[userID]
	if user == nil {
		checkErr(ErrContentNotFound)
	}
	return user
}

func getUserFromAccount(w http.ResponseWriter, name string) *User {
	user := an2user[name]
	if user == nil {
		checkErr(ErrContentNotFound)
	}
	return user
}

func isFriend(w http.ResponseWriter, r *http.Request, anotherID int) bool {
	session := getSession(w, r)
	id, ok := session.Values["user_id"].(int)
	if !ok {
		log.Println("Couldn't convert session user_id to int")
		return false
	}
	m, ok := rels[id]
	if !ok {
		return false
	}
	_, ok = m[anotherID]
	return ok
}

func isFriendAccount(w http.ResponseWriter, r *http.Request, name string) bool {
	user := getUserFromAccount(w, name)
	if user == nil {
		return false
	}
	return isFriend(w, r, user.ID)
}

func getFriendIds(userID int) []interface{} {
	friendIds := make([]interface{}, 0)
	for i, t := range rels[userID] {
		if !t.IsZero() {
			friendIds = append(friendIds, i)
		}
	}
	return friendIds
}

func permitted(w http.ResponseWriter, r *http.Request, anotherID int) bool {
	user := getCurrentUser(w, r)
	if anotherID == user.ID {
		return true
	}
	return isFriend(w, r, anotherID)
}

func markFootprint(w http.ResponseWriter, r *http.Request, id int) {
	user := getCurrentUser(w, r)
	if user.ID != id {
		_, err := db.Exec(`REPLACE INTO footprints (user_id,owner_id,date) VALUES (?,?,NOW())`, id, user.ID)
		checkErr(err)
	}
}

func myHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rcv := recover()
			if rcv != nil {
				switch {
				case rcv == ErrAuthentication:
					session := getSession(w, r)
					delete(session.Values, "user_id")
					session.Save(r, w)
					render(w, r, http.StatusUnauthorized, "login.html", struct{ Message string }{"ログインに失敗しました"})
					return
				case rcv == ErrPermissionDenied:
					render(w, r, http.StatusForbidden, "error.html", struct{ Message string }{"友人のみしかアクセスできません"})
					return
				case rcv == ErrContentNotFound:
					render(w, r, http.StatusNotFound, "error.html", struct{ Message string }{"要求されたコンテンツは存在しません"})
					return
				default:
					var msg string
					if e, ok := rcv.(runtime.Error); ok {
						msg = e.Error()
					}
					if s, ok := rcv.(string); ok {
						msg = s
					}
					msg = rcv.(error).Error()
					http.Error(w, msg, http.StatusInternalServerError)
				}
			}
		}()
		fn(w, r)
	}
}

func getSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isucon5q-go.session")
	return session
}

func getTemplatePath(file string) string {
	return path.Join("templates", file)
}

func render(w http.ResponseWriter, r *http.Request, status int, file string, data interface{}) {
	fmap := template.FuncMap{
		"getUser": func(id int) *User {
			return getUser(w, id)
		},
		"getCurrentUser": func() *User {
			return getCurrentUser(w, r)
		},
		"isFriend": func(id int) bool {
			return isFriend(w, r, id)
		},
		"prefectures": func() []string {
			return prefs
		},
		"substring": func(s string, l int) string {
			if len(s) > l {
				return s[:l]
			}
			return s
		},
		"split": strings.Split,
		"getEntry": func(id int) Entry {
			row := db.QueryRow(`SELECT * FROM entries WHERE id=?`, id)
			var entryID, userID, private int
			var body, title string
			var createdAt time.Time
			checkErr(row.Scan(&entryID, &userID, &private, &body, &createdAt, &title))
			return Entry{id, userID, private == 1, title, body, createdAt}
		},
		"numComments": func(id int) int {
			row := db.QueryRow(`SELECT COUNT(*) AS c FROM comments WHERE entry_id = ?`, id)
			var n int
			checkErr(row.Scan(&n))
			return n
		},
	}
	tpl := template.Must(template.New(file).Funcs(fmap).ParseFiles(getTemplatePath(file), getTemplatePath("header.html")))
	w.WriteHeader(status)
	checkErr(tpl.Execute(w, data))
}

func GetLogin(w http.ResponseWriter, r *http.Request) {
	render(w, r, http.StatusOK, "login.html", struct{ Message string }{"高負荷に耐えられるSNSコミュニティサイトへようこそ!"})
}

func PostLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	passwd := r.FormValue("password")
	authenticate(w, r, email, passwd)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func GetIndex(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)

	prof := Profile{}
	row := db.QueryRow(`SELECT * FROM profiles WHERE user_id = ?`, user.ID)
	err := row.Scan(&prof.UserID, &prof.FirstName, &prof.LastName, &prof.Sex, &prof.Birthday, &prof.Pref, &prof.UpdatedAt)
	if err != sql.ErrNoRows {
		checkErr(err)
	}

	rows, err := db.Query(`SELECT id, user_id, private, title, created_at FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	entries := make([]Entry, 0, 5)
	for rows.Next() {
		var id, userID, private int
		var title string
		var createdAt time.Time
		checkErr(rows.Scan(&id, &userID, &private, &title, &createdAt))
		entries = append(entries, Entry{id, userID, private == 1, title, "", createdAt})
	}
	rows.Close()

	rows, err = db.Query(`SELECT c.id AS id, c.entry_id AS entry_id, c.user_id AS user_id, c.comment AS comment, c.created_at AS created_at
FROM comments c
JOIN entries e ON c.entry_id = e.id
WHERE e.user_id = ?
ORDER BY c.created_at DESC
LIMIT 10`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	commentsForMe := make([]Comment, 0, 10)
	for rows.Next() {
		c := Comment{}
		checkErr(rows.Scan(&c.ID, &c.EntryID, &c.UserID, &c.Comment, &c.CreatedAt))
		commentsForMe = append(commentsForMe, c)
	}
	rows.Close()

	friendIds := getFriendIds(user.ID)
	entriesOfFriends := make([]Entry, 0, 10)
	if len(friendIds) > 0 {
		sqlStr := "SELECT id, user_id, private, title, created_at FROM entries\n" +
		"WHERE user_id IN (?" + strings.Repeat(",?", len(friendIds)-1) + ")\n" +
		"ORDER BY id DESC LIMIT 10"
		rows, err = db.Query(sqlStr, friendIds...)
		if err != sql.ErrNoRows {
			checkErr(err)
		}
		for rows.Next() {
			var id, userID, private int
			var title string
			var createdAt time.Time
			checkErr(rows.Scan(&id, &userID, &private, &title, &createdAt))
			entriesOfFriends = append(entriesOfFriends, Entry{id, userID, private == 1, title, "", createdAt})
		}
		rows.Close()
	}

	commentsOfFriends := make([]Comment, 0, 10)
	if len(friendIds) > 0 {
		sqlStr:=
		"SELECT c.id, c.entry_id, c.user_id, c.comment, c.created_at FROM comments c\n" +
		"JOIN entries e ON c.entry_id = e.id\n" +
		"WHERE c.user_id IN (?" + strings.Repeat(",?", len(friendIds)-1) + ")\n" +
		"AND (\n" +
		"  e.private = 0\n" +
		"  OR\n" +
		"  e.private = 1 AND (e.user_id = ? OR e.user_id IN (?" + strings.Repeat(",?", len(friendIds)-1) + "))\n" +
		")\n" +
		"ORDER BY c.id DESC LIMIT 10"
		args := friendIds
		args = append(args, user.ID)
		args = append(args, friendIds...)
		rows, err = db.Query(sqlStr, args...)
		if err != sql.ErrNoRows {
			checkErr(err)
		}
		for rows.Next() {
			c := Comment{}
			checkErr(rows.Scan(&c.ID, &c.EntryID, &c.UserID, &c.Comment, &c.CreatedAt))
			commentsOfFriends = append(commentsOfFriends, c)
		}
		rows.Close()
	}

	friends := getFriendsFromRelations(user.ID)

	rows, err = db.Query(`SELECT user_id, owner_id, date, created_at AS updated
FROM footprints
WHERE user_id = ?
ORDER BY updated DESC
LIMIT 10`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	footprints := make([]Footprint, 0, 10)
	for rows.Next() {
		fp := Footprint{}
		checkErr(rows.Scan(&fp.UserID, &fp.OwnerID, &fp.CreatedAt, &fp.Updated))
		footprints = append(footprints, fp)
	}
	rows.Close()

	render(w, r, http.StatusOK, "index.html", struct {
		User              User
		Profile           Profile
		Entries           []Entry
		CommentsForMe     []Comment
		EntriesOfFriends  []Entry
		CommentsOfFriends []Comment
		Friends           []Friend
		Footprints        []Footprint
	}{
		*user, prof, entries, commentsForMe, entriesOfFriends, commentsOfFriends, friends, footprints,
	})
}

func GetProfile(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	account := mux.Vars(r)["account_name"]
	owner := getUserFromAccount(w, account)
	row := db.QueryRow(`SELECT * FROM profiles WHERE user_id = ?`, owner.ID)
	prof := Profile{}
	err := row.Scan(&prof.UserID, &prof.FirstName, &prof.LastName, &prof.Sex, &prof.Birthday, &prof.Pref, &prof.UpdatedAt)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	var query string
	if permitted(w, r, owner.ID) {
		query = `SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5`
	} else {
		query = `SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at LIMIT 5`
	}
	rows, err := db.Query(query, owner.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	entries := make([]Entry, 0, 5)
	for rows.Next() {
		var id, userID, private int
		var body, title string
		var createdAt time.Time
		checkErr(rows.Scan(&id, &userID, &private, &body, &createdAt, &title))
		entry := Entry{id, userID, private == 1, title, body, createdAt}
		entries = append(entries, entry)
	}
	rows.Close()

	markFootprint(w, r, owner.ID)

	render(w, r, http.StatusOK, "profile.html", struct {
		Owner   User
		Profile Profile
		Entries []Entry
		Private bool
	}{
		*owner, prof, entries, permitted(w, r, owner.ID),
	})
}

func PostProfile(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}
	user := getCurrentUser(w, r)
	account := mux.Vars(r)["account_name"]
	if account != user.AccountName {
		checkErr(ErrPermissionDenied)
	}
	query := `UPDATE profiles
SET first_name=?, last_name=?, sex=?, birthday=?, pref=?, updated_at=CURRENT_TIMESTAMP()
WHERE user_id = ?`
	birth := r.FormValue("birthday")
	firstName := r.FormValue("first_name")
	lastName := r.FormValue("last_name")
	sex := r.FormValue("sex")
	pref := r.FormValue("pref")
	_, err := db.Exec(query, firstName, lastName, sex, birth, pref, user.ID)
	checkErr(err)
	// TODO should escape the account name?
	http.Redirect(w, r, "/profile/"+account, http.StatusSeeOther)
}

func ListEntries(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	account := mux.Vars(r)["account_name"]
	owner := getUserFromAccount(w, account)
	var query string
	if permitted(w, r, owner.ID) {
		query = `SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`
	} else {
		query = `SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at DESC LIMIT 20`
	}
	rows, err := db.Query(query, owner.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	entries := make([]Entry, 0, 20)
	for rows.Next() {
		var id, userID, private int
		var body, title string
		var createdAt time.Time
		checkErr(rows.Scan(&id, &userID, &private, &body, &createdAt, &title))
		entry := Entry{id, userID, private == 1, title, body, createdAt}
		entries = append(entries, entry)
	}
	rows.Close()

	markFootprint(w, r, owner.ID)

	render(w, r, http.StatusOK, "entries.html", struct {
		Owner   *User
		Entries []Entry
		Myself  bool
	}{owner, entries, getCurrentUser(w, r).ID == owner.ID})
}

func GetEntry(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}
	entryID := mux.Vars(r)["entry_id"]
	row := db.QueryRow(`SELECT * FROM entries WHERE id = ?`, entryID)
	var id, userID, private int
	var body, title string
	var createdAt time.Time
	err := row.Scan(&id, &userID, &private, &body, &createdAt, &title)
	if err == sql.ErrNoRows {
		checkErr(ErrContentNotFound)
	}
	checkErr(err)
	entry := Entry{id, userID, private == 1, title, body, createdAt}
	owner := getUser(w, entry.UserID)
	if entry.Private {
		if !permitted(w, r, owner.ID) {
			checkErr(ErrPermissionDenied)
		}
	}
	rows, err := db.Query(`SELECT * FROM comments WHERE entry_id = ?`, entry.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	comments := make([]Comment, 0, 10)
	for rows.Next() {
		c := Comment{}
		checkErr(rows.Scan(&c.ID, &c.EntryID, &c.UserID, &c.Comment, &c.CreatedAt))
		comments = append(comments, c)
	}
	rows.Close()

	markFootprint(w, r, owner.ID)

	render(w, r, http.StatusOK, "entry.html", struct {
		Owner    *User
		Entry    Entry
		Comments []Comment
	}{owner, entry, comments})
}

func PostEntry(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)
	title := r.FormValue("title")
	if title == "" {
		title = "タイトルなし"
	}
	content := r.FormValue("content")
	var private int
	if r.FormValue("private") == "" {
		private = 0
	} else {
		private = 1
	}
	_, err := db.Exec(`INSERT INTO entries (user_id, private, title, body) VALUES (?,?,?,?)`, user.ID, private, title, content)
	checkErr(err)
	http.Redirect(w, r, "/diary/entries/"+user.AccountName, http.StatusSeeOther)
}

func PostComment(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	entryID := mux.Vars(r)["entry_id"]
	row := db.QueryRow(`SELECT * FROM entries WHERE id = ?`, entryID)
	var id, userID, private int
	var body, title string
	var createdAt time.Time
	err := row.Scan(&id, &userID, &private, &body, &createdAt, &title)
	if err == sql.ErrNoRows {
		checkErr(ErrContentNotFound)
	}
	checkErr(err)

	entry := Entry{id, userID, private == 1, title, body, createdAt}
	owner := getUser(w, entry.UserID)
	if entry.Private {
		if !permitted(w, r, owner.ID) {
			checkErr(ErrPermissionDenied)
		}
	}
	user := getCurrentUser(w, r)

	_, err = db.Exec(`INSERT INTO comments (entry_id, user_id, comment) VALUES (?,?,?)`, entry.ID, user.ID, r.FormValue("comment"))
	checkErr(err)
	http.Redirect(w, r, "/diary/entry/"+strconv.Itoa(entry.ID), http.StatusSeeOther)
}

func GetFootprints(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)
	footprints := make([]Footprint, 0, 50)
	rows, err := db.Query(`SELECT user_id, owner_id, date, created_at AS updated
FROM footprints
WHERE user_id = ?
ORDER BY updated DESC
LIMIT 50`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	for rows.Next() {
		fp := Footprint{}
		checkErr(rows.Scan(&fp.UserID, &fp.OwnerID, &fp.CreatedAt, &fp.Updated))
		footprints = append(footprints, fp)
	}
	rows.Close()
	render(w, r, http.StatusOK, "footprints.html", struct{ Footprints []Footprint }{footprints})
}
func GetFriends(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)
	friends := getFriendsFromRelations(user.ID)
	render(w, r, http.StatusOK, "friends.html", struct{ Friends []Friend }{friends})
}

func PostFriends(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)
	anotherAccount := mux.Vars(r)["account_name"]
	another := getUserFromAccount(w, anotherAccount)
	if createRelationIfNotExists(user.ID, another.ID) {
		http.Redirect(w, r, "/friends", http.StatusSeeOther)
	}
}

func GetInitialize(w http.ResponseWriter, r *http.Request) {
	db.Exec("DELETE FROM relations WHERE id > 500000")
	db.Exec("DELETE FROM footprints WHERE id > 500000")
	db.Exec("DELETE FROM entries WHERE id > 500000")
	db.Exec("DELETE FROM comments WHERE id > 1500000")
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		log.Println(r.RequestURI)
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

func finalize(ln net.Listener) {
	if err := ln.Close(); err != nil {
		log.Fatalf("Failed to close listener: %v", err)
	}
}

func main() {
	// host := os.Getenv("ISUCON5_DB_HOST")
	// if host == "" {
	// 	host = "localhost"
	// }
	// portstr := os.Getenv("ISUCON5_DB_PORT")
	// if portstr == "" {
	// 	portstr = "3306"
	// }
	// port, err := strconv.Atoi(portstr)
	// if err != nil {
	// 	log.Fatalf("Failed to read DB port number from an environment variable ISUCON5_DB_PORT.\nError: %s", err.Error())
	// }
	user := os.Getenv("ISUCON5_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCON5_DB_PASSWORD")
	dbname := os.Getenv("ISUCON5_DB_NAME")
	if dbname == "" {
		dbname = "isucon5q"
	}
	ssecret := os.Getenv("ISUCON5_SESSION_SECRET")
	if ssecret == "" {
		ssecret = "beermoris"
	}

	var err error
	db, err = sql.Open("mysql", user+":"+password+"@unix(/var/run/mysqld/mysqld.sock)/"+dbname+"?loc=Local&parseTime=true")
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	if rels, err = loadRelations(); err != nil {
		log.Printf("Failed to load relations: %v\n", err)
		return
	}
	if err = loadUsers(); err != nil {
		log.Printf("Failed to load users: %v\n", err)
		return
	}

	store = sessions.NewCookieStore([]byte(ssecret))

	r := mux.NewRouter()

	l := r.Path("/login").Subrouter()
	l.Methods("GET").HandlerFunc(myHandler(GetLogin))
	l.Methods("POST").HandlerFunc(myHandler(PostLogin))
	r.Path("/logout").Methods("GET").HandlerFunc(myHandler(GetLogout))

	p := r.Path("/profile/{account_name}").Subrouter()
	p.Methods("GET").HandlerFunc(myHandler(GetProfile))
	p.Methods("POST").HandlerFunc(myHandler(PostProfile))

	d := r.PathPrefix("/diary").Subrouter()
	d.HandleFunc("/entries/{account_name}", myHandler(ListEntries)).Methods("GET")
	d.HandleFunc("/entry", myHandler(PostEntry)).Methods("POST")
	d.HandleFunc("/entry/{entry_id}", myHandler(GetEntry)).Methods("GET")

	d.HandleFunc("/comment/{entry_id}", myHandler(PostComment)).Methods("POST")

	r.HandleFunc("/footprints", myHandler(GetFootprints)).Methods("GET")

	r.HandleFunc("/friends", myHandler(GetFriends)).Methods("GET")
	r.HandleFunc("/friends/{account_name}", myHandler(PostFriends)).Methods("POST")

	r.HandleFunc("/initialize", myHandler(GetInitialize))
	r.HandleFunc("/", myHandler(GetIndex))
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("../static")))

	r.Use(loggingMiddleware)


	// use unix domain socket
	ln, err := net.Listen("unix", "/var/run/isuxi/go.sock")
	if err != nil {
		log.Fatalf("Failed to listen unix socket: %v", err)
	}
	defer finalize(ln)

	c := make(chan os.Signal, 2)
	go func(ln net.Listener, c chan os.Signal) {
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		finalize(ln)
		os.Exit(1)
	}(ln, c)

	log.Println("Started server")
	log.Fatal(http.Serve(ln, r))
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
