package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	clientID     = os.Getenv("OIDC_CLIENT_ID")     // 環境変数から取得
	clientSecret = os.Getenv("OIDC_CLIENT_SECRET") // 環境変数から取得
	redirectURL  = "http://localhost:8080/callback"

	provider *oidc.Provider
	oauth2Config oauth2.Config
)

func main() {
	var err error
	provider, err = oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("cid:%v,cs:%v\n",clientID,clientSecret)
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/userinfo", userInfoHandler)

	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ホームページ
func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

// OIDC ログイン処理
func loginHandler(w http.ResponseWriter, r *http.Request) {
	url := oauth2Config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

// OIDC コールバック処理
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	code := r.URL.Query().Get("code")

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// JWT を Cookie に保存
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    token.AccessToken,
		HttpOnly: true,
		Path:     "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
	http.Redirect(w,r,"http://localhost:8080",301)
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("jwt")
	if err != nil {
		http.Error(w, "認証に失敗しました", http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cookie.Value}))
	if err != nil {
		http.Error(w, "認証に失敗しました", http.StatusInternalServerError)
		return
	}

	// レスポンスを HTML に変更（HTMX に適した形）
	response := fmt.Sprintf(`
        <p>ユーザー名: %s</p>
        <p>Email: %s</p>
    `, userInfo.Subject, userInfo.Email)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(response))
}

/*
// ユーザー情報取得
func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("userInfo Call")
	cookie, err := r.Cookie("jwt")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cookie.Value}))
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}
*/
