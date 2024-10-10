package main

import (
	"log"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	_"github.com/godror/godror"
)

func main() {
	oracleDSN := "system/123456789@localhost:1521/ORCL"

	db, err := sqlx.Connect("godror", oracleDSN)
	if err != nil {
		log.Fatal("Failed to connect to database", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to Ping Oracle", err)
	}

	log.Println("Successfully connected to Oracle!")
}
	// If we got here, the connection was successful.
