package main

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"

	"github.com/go-session/redis/v3"
	"github.com/go-session/session/v3"
)

type config struct {
	Address    string            `toml:"address"`
	CookieName string            `toml:"cookie_name"`
	Redis      redisConfig       `toml:"redis"`
	Jellyfin   jellyfinConfig    `toml:"jellyfin"`
	Targets    map[string]target `toml:"targets"`
}

type redisConfig struct {
	Network  string `toml:"network"`
	Addr     string `toml:"addr"`
	Password string `toml:"password"`
	DB       int    `toml:"db"`
}

type jellyfinConfig struct {
	BaseURL string `toml:"base_url"`
	Key     string `toml:"key"`
}

type target struct {
	BaseURL      string `toml:"base_url"`
	TemplateFile string `toml:"template_file"`
}

type templateData struct {
}

type jellyfinAuthResponse struct {
	User struct {
		ID string `json:"Id"`
	}
}

var fallbackTemplate = `<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8" />
		<meta name="robots" content="noindex, nofollow" />
		<title>websieve</title>
	</head>
	<body>
		<main>
			<form action method="POST">
				<input type="text" name="username" required />
				<input type="password" name="password" required />

				<button type="submit">Login</button>
			</form>
		</main>
	</body>
</html>
`

var hbhHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime)
	log.SetPrefix("websieve: ")

	c := config{
		Address:    "localhost:8080",
		CookieName: "websieve",
	}

	paths := []string{
		"websieve.toml",
		"/etc/websieve/websieve.toml",
	}

	var cf string

	app := &cli.App{
		Name:  "websieve",
		Usage: "add authentication to web applications",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Usage:       "configuration file",
				Destination: &cf,
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "run",
				Usage: "run websieve",
				Action: func(ctx *cli.Context) error {
					readConfig(cf, paths, toml.Unmarshal, &c)

					session.InitManager(
						session.SetStore(redis.NewRedisStore(&redis.Options{
							Network:  c.Redis.Network,
							Addr:     c.Redis.Addr,
							Password: c.Redis.Password,
							DB:       c.Redis.DB,
						})),
						session.SetCookieName(c.CookieName),
					)

					jellyURL, err := url.Parse(c.Jellyfin.BaseURL)
					if err != nil {
						log.Fatalf("Cannot parse base URL: %s", err.Error())
					}

					re := regexp.MustCompile(`^[^/]+$`)
					prefixre := regexp.MustCompile(`^/[^/]+`)
					for key, target := range c.Targets {
						if !re.Match([]byte(key)) {
							log.Fatalf("Target key did not match requirements: %s", re.String())
						}

						t := template.New("")

						var text string
						if target.TemplateFile != "" {
							buf, err := os.ReadFile(target.TemplateFile)
							if err == nil {
								text = string(buf)
							} else {
								log.Print("Cannot read template file, falling back to default template")
								text = fallbackTemplate
							}
						} else {
							text = fallbackTemplate
						}

						t.Parse(text)

						http.HandleFunc("/"+key+"/", func(w http.ResponseWriter, srcreq *http.Request) {
							store, err := session.Start(context.Background(), w, srcreq)
							if err != nil {
								http.Error(w, err.Error(), http.StatusBadGateway)
								log.Printf("Error while starting session: %s", err.Error())
								return
							}

							relative := prefixre.ReplaceAllString(srcreq.RequestURI, "")

							authenticated := false

							userID, ok := store.Get("user_id")
							if ok {
								usersEndpoint := cloneURL(jellyURL)
								usersEndpoint.Path, err = url.JoinPath(usersEndpoint.Path, "Users", userID.(string))
								if err != nil {
									http.Error(w, err.Error(), http.StatusInternalServerError)
									log.Printf("Error while attempting to create new path: %s", err.Error())
									return
								}

								client := &http.Client{}
								req, _ := http.NewRequest("GET", usersEndpoint.String(), nil)
								req.Header.Set("x-emby-authorization", "MediaBrowser Client=\"JellyAuth\", Device=\"JellyAuth\", DeviceId=\"1\", Version=\"0.0.1\"")
								req.Header.Set("Authorization", "Mediabrowser Token="+c.Jellyfin.Key)
								resp, _ := client.Do(req)
								if err != nil {
									http.Error(w, err.Error(), http.StatusInternalServerError)
									log.Printf("Error while validating user: %s", err.Error())
									return
								}

								if resp.StatusCode != 200 {
									log.Printf("Jellyfin returned %s", resp.Status)
									http.Redirect(w, srcreq, relative, http.StatusSeeOther)
									return
								} else {
									authenticated = true
								}
							}

							if !authenticated {
								if srcreq.Method == "GET" {
									w.WriteHeader(http.StatusForbidden)

									t.Execute(w, templateData{})

									return
								} else if srcreq.Method == "POST" {
									fusername := srcreq.FormValue("username")
									fpassword := srcreq.FormValue("password")

									authEndpoint := cloneURL(jellyURL)
									authEndpoint.Path, err = url.JoinPath(authEndpoint.Path, "Users", "AuthenticateByName")
									if err != nil {
										http.Error(w, err.Error(), http.StatusInternalServerError)
										log.Printf("Error while attempting to create new path: %s", err.Error())
										return
									}

									body, err := json.Marshal(map[string]interface{}{
										"Username": fusername,
										"Pw":       fpassword,
									})
									if err != nil {
										http.Error(w, err.Error(), http.StatusInternalServerError)
										log.Printf("Could not marshal request body to JSON: %s", err.Error())
										return
									}

									client := &http.Client{}
									req, _ := http.NewRequest("POST", authEndpoint.String(), bytes.NewReader(body))
									req.Header.Set("x-emby-authorization", "MediaBrowser Client=\"JellyAuth\", Device=\"JellyAuth\", DeviceId=\"1\", Version=\"0.0.1\"")
									req.Header.Set("Authorization", "Mediabrowser Token="+c.Jellyfin.Key)
									req.Header.Set("Content-Type", "application/json")
									req.Header.Set("Accept", "application/json")
									resp, err := client.Do(req)
									if err != nil {
										http.Error(w, err.Error(), http.StatusInternalServerError)
										log.Printf("Error while validating user: %s", err.Error())
										return
									}

									if resp.StatusCode != 200 {
										log.Printf("Jellyfin returned %s", resp.Status)
										http.Redirect(w, srcreq, relative, http.StatusSeeOther)
										return
									} else {
										authenticated = true
									}

									encBody, err := io.ReadAll(resp.Body)
									if err != nil {
										http.Error(w, err.Error(), http.StatusInternalServerError)
										log.Printf("Could not read response body: %s", err.Error())
										return
									}
									decBody := jellyfinAuthResponse{}
									json.Unmarshal(encBody, &decBody)

									store.Set("user_id", decBody.User.ID)
									err = store.Save()
									if err != nil {
										http.Error(w, err.Error(), http.StatusInternalServerError)
										log.Printf("Could not save data to session: %s", err.Error())
										return
									}

									http.Redirect(w, srcreq, relative, http.StatusSeeOther)
									return
								} else {
									http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
									log.Print("Method not allowed")
									return
								}
							}

							t, err := url.Parse(target.BaseURL)
							if err != nil {
								log.Fatalf("Cannot parse base URL: %s", err.Error())
							}
							t.Path, err = url.JoinPath(t.Path, strings.TrimPrefix(srcreq.URL.Path, "/"+key))
							if err != nil {
								http.Error(w, err.Error(), http.StatusInternalServerError)
								log.Printf("Error while attempting to create new path: %s", err.Error())
								return
							}

							destreq := srcreq.Clone(srcreq.Context())
							destreq.URL = t
							destreq.RequestURI = ""
							destreq.Host = destreq.URL.Host

							for _, h := range hbhHeaders {
								destreq.Header.Del(h)
							}

							if host, _, err := net.SplitHostPort(srcreq.RemoteAddr); err == nil {
								if prior, ok := srcreq.Header["X-Forwarded-For"]; ok {
									host = strings.Join(prior, ", ") + ", " + host
								}
								srcreq.Header.Set("X-Forwarded-For", host)
							}

							hc := http.Client{Timeout: time.Duration(1) * time.Second}
							hc.Do(destreq)

							resp, err := hc.Do(destreq)
							if err != nil {
								http.Error(w, err.Error(), http.StatusBadGateway)
								log.Printf("Error while proxying request: %s", err.Error())
								return
							}
							defer resp.Body.Close()

							wh := w.Header()
							for k, vv := range resp.Header {
								if !slices.Contains(hbhHeaders, k) {
									for _, v := range vv {
										wh.Add(k, v)
									}
								}
							}

							w.WriteHeader(resp.StatusCode)
							io.Copy(w, resp.Body)
						})
					}

					if err := http.ListenAndServe(c.Address, nil); err != nil {
						log.Fatalf("Listen error: %s", err.Error())
					}

					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Argument error: %s", err.Error())
	}
}

func readConfig(path string, paths []string, unmarshal func(data []byte, v interface{}) error, v interface{}) {
	var err error

	if path == "" {
		for _, p := range paths {
			_, err = os.Stat(p)
			if err != nil {
				continue
			}

			path = p
		}

		if path == "" {
			log.Fatal("Unable to locate configuration file")
		}
	} else {
		_, err = os.Stat(path)
		if err != nil {
			log.Fatalf("Could not stat %s: %s", path, err.Error())
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Unable to read configuration file %s: %s", path, err.Error())
	}

	err = unmarshal(content, v)
	if err != nil {
		log.Fatalf("Unable to unmarshal configuration file %s: %s", path, err.Error())
	}
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	if u.User != nil {
		u2.User = new(url.Userinfo)
		*u2.User = *u.User
	}
	return u2
}
