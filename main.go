package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slices"
	"golang.org/x/term"

	"github.com/go-session/redis/v3"
	"github.com/go-session/session/v3"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type config struct {
	Address      string            `toml:"address"`
	DatabaseFile string            `toml:"database_file"`
	CookieName   string            `toml:"cookie_name"`
	Redis        redisConfig       `toml:"redis"`
	Targets      map[string]target `toml:"targets"`
}

type redisConfig struct {
	Network  string `toml:"network"`
	Addr     string `toml:"addr"`
	Password string `toml:"password"`
	DB       int    `toml:"db"`
}

type target struct {
	BaseURL      string `toml:"base_url"`
	TemplateFile string `toml:"template_file"`
}

type templateData struct {
}

type user struct {
	ID       int
	Name     string
	Password string
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
	logger := log.New(os.Stderr, "websieve: ", log.Lshortfile)

	c := config{
		Address:      "localhost:8080",
		DatabaseFile: "websieve.db",
		CookieName:   "websieve",
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
					readConfig(cf, paths, toml.Unmarshal, &c, logger)
					db := getDB(c, logger)

					session.InitManager(
						session.SetStore(redis.NewRedisStore(&redis.Options{
							Network:  c.Redis.Network,
							Addr:     c.Redis.Addr,
							Password: c.Redis.Password,
							DB:       c.Redis.DB,
						})),
						session.SetCookieName(c.CookieName),
					)

					re := regexp.MustCompile(`^[^/]+$`)
					prefixre := regexp.MustCompile(`^/[^/]+`)
					for key, target := range c.Targets {
						if !re.Match([]byte(key)) {
							logger.Fatalf("Target key did not match requirements: %s", re.String())
						}

						t := template.New("")

						var text string
						if target.TemplateFile != "" {
							buf, err := os.ReadFile(target.TemplateFile)
							if err == nil {
								text = string(buf)
							} else {
								logger.Print("Cannot read template file, falling back to default template")
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
								logger.Printf("Error while starting session: %s", err.Error())
								return
							}

							relative := prefixre.ReplaceAllString(srcreq.RequestURI, "")

							authenticated := false

							userID, ok := store.Get("user_id")
							if ok {
								row := db.QueryRow(`
									SELECT id
									FROM user
									WHERE id = ?
								`, userID)

								err := row.Err()
								if err == nil {
									authenticated = true
								} else if !errors.Is(err, sql.ErrNoRows) {
									logger.Fatalf("Error while scanning row: %s", err.Error())
								}
							}

							if !authenticated {
								if srcreq.Method == "GET" {
									w.WriteHeader(http.StatusForbidden)

									t.Execute(w, templateData{})

									return
								} else if srcreq.Method == "POST" {
									fuser := user{
										Name:     srcreq.FormValue("username"),
										Password: srcreq.FormValue("password"),
									}

									row := db.QueryRow(`
										SELECT id, password
										FROM user
										WHERE name = ?
									`, fuser.Name)

									var user user
									err = row.Scan(&user.ID, &user.Password)
									if err != nil {
										if !errors.Is(err, sql.ErrNoRows) {
											logger.Fatalf("Error while scanning row: %s", err.Error())
										} else {
											logger.Printf("User %s not found", fuser.Name)
											http.Redirect(w, srcreq, relative, http.StatusSeeOther)
											return
										}
									}

									if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(fuser.Password)) != nil {
										http.Redirect(w, srcreq, relative, http.StatusSeeOther)
										return
									}

									store.Set("user_id", user.ID)
									err = store.Save()
									if err != nil {
										http.Error(w, err.Error(), http.StatusInternalServerError)
										logger.Printf("Could not save data to session: %s", err.Error())
										return
									}

									http.Redirect(w, srcreq, relative, http.StatusSeeOther)
									return
								} else {
									http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
									logger.Print("Method not allowed")
									return
								}
							}

							t, err := url.Parse(target.BaseURL)
							if err != nil {
								logger.Fatalf("Cannot parse base URL: %s", err.Error())
							}
							t.Path, err = url.JoinPath(t.Path, strings.TrimPrefix(srcreq.URL.Path, "/"+key))
							if err != nil {
								http.Error(w, err.Error(), http.StatusInternalServerError)
								logger.Printf("Error while attempting to create new path: %s", err.Error())
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
								logger.Printf("Error while proxying request: %s", err.Error())
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
						logger.Fatalf("Listen error: %s", err.Error())
					}

					return nil
				},
			},
			{
				Name:    "user",
				Aliases: []string{"u"},
				Usage:   "user",
				Subcommands: []*cli.Command{
					{
						Name:  "create",
						Usage: "create a new user",
						Action: func(ctx *cli.Context) error {
							readConfig(cf, paths, toml.Unmarshal, &c, logger)
							db := getDB(c, logger)

							for _, name := range ctx.Args().Slice() {
								fmt.Fprintf(os.Stderr, "Enter password for new user %s: ", name)
								bytePassword, err := term.ReadPassword(int(syscall.Stdin))
								fmt.Fprint(os.Stderr, "\n")
								if err != nil {
									return err
								}
								hashedPassword, err := bcrypt.GenerateFromPassword(bytePassword, 12)
								if err != nil {
									return err
								}

								_, err = db.Exec(`
									INSERT INTO user (name, password)
									VALUES (?, ?)
								`, name, hashedPassword)
								if err != nil {
									return err
								}
							}

							return nil
						},
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Fatalf("Argument error: %s", err.Error())
	}
}

func readConfig(path string, paths []string, unmarshal func(data []byte, v interface{}) error, v interface{}, logger *log.Logger) {
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
			logger.Fatal("Unable to locate configuration file")
		}
	} else {
		_, err = os.Stat(path)
		if err != nil {
			logger.Fatalf("Could not stat %s: %s", path, err.Error())
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		logger.Fatalf("Unable to read configuration file %s: %s", path, err.Error())
	}

	err = unmarshal(content, v)
	if err != nil {
		logger.Fatalf("Unable to unmarshal configuration file %s: %s", path, err.Error())
	}
}

func getDB(c config, logger *log.Logger) *sql.DB {
	db, err := sql.Open("sqlite3", c.DatabaseFile)
	if err != nil {
		logger.Fatalf("Error while opening database: %s", err.Error())
	}
	err = initDB(db)
	if err != nil {
		logger.Fatalf("Could not initialize the database: %s", err.Error())
	}

	return db
}

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS user (
			id INTEGER NOT NULL,
			name TEXT NOT NULL,
			password TEXT NOT NULL,
			PRIMARY KEY (id),
			UNIQUE (name)
		);
	`)

	if err != nil {
		return err
	}

	return nil
}
