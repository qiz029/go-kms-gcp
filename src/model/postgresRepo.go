package model

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

var db *sql.DB

func Start() {
	engine, err := sql.Open("postgres", "user=postgres password=postgres dbname=postgres sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	db = engine
	if err = db.Ping(); err != nil {
		panic(err)
	} else {
		fmt.Println("DB Connected")
	}

	cmkSQLStatement := "CREATE TABLE IF NOT EXISTS masterkeys (" +
		"Cmk_id serial NOT NULL, " +
		"Cmk_name VARCHAR(255) UNIQUE NOT NULL, " +
		"Expiration_date TIMESTAMP, " +
		"PRIMARY KEY (Cmk_id)" +
		")"
	kekSQLStatement := "CREATE TABLE IF NOT EXISTS keks (" +
		"Project_id serial NOT NULL, " +
		"Cmk_id serial NOT NULL, " +
		"Encrypted_key VARCHAR(255), " +
		"PRIMARY KEY (Project_id, Cmk_id), " +
		"CONSTRAINT cmk_id_fkey FOREIGN KEY (Cmk_id)" +
		"	REFERENCES masterkeys (Cmk_id) MATCH SIMPLE" +
		"	ON UPDATE NO ACTION ON DELETE NO ACTION" +
		")"
	_, err = db.Query(cmkSQLStatement)
	if err != nil {
		panic(err)
	}
	_, err = db.Query(kekSQLStatement)
	if err != nil {
		panic(err)
	}
	log.Print("Database stand up done!")
}

func StoreCmk(cmk_id int, cmk_name string, expire_date string) bool {
	storeStmt, err := db.Prepare("INSERT INTO public.masterkeys(" +
		"cmk_id, cmk_name, expiration_date)" +
		"VALUES ($1, $2, $3);")
	if err != nil {
		panic(err.Error())
	}
	defer storeStmt.Close()
	_, err = storeStmt.Query(cmk_id, cmk_name, expire_date)
	if err != nil {
		panic(err.Error())
	}
	return true
}

func StoreKek(project_id int, encrypted_key string, cmk_id int) bool {
	storeStmt, err := db.Prepare("INSERT INTO public.keks(" +
		"project_id, cmk_id, encrypted_key)" +
		"VALUES ($1, $2, $3);")
	if err != nil {
		panic(err.Error())
	}
	defer storeStmt.Close()
	_, err = storeStmt.Exec(project_id, cmk_id, encrypted_key)
	if err != nil {
		return false
	}
	return true
}

func GetCmk(cmk_id int) string {
	cmk_name_row, err1 := db.Query("SELECT cmk_name FROM public.masterkeys WHERE cmk_id=$1;", cmk_id)
	if err1 != nil {
		panic(err1.Error())
	}
	var cmk_name string
	cmk_name_row.Next()
	cmk_name_row.Scan(&cmk_name)

	if cmk_name == "" {
		return ""
	}
	return cmk_name

}

func GetKek(cmk_id int, pid int) string {
	encrypted_key_row, err1 := db.Query("SELECT encrypted_key FROM public.keks WHERE cmk_id=$1 AND project_id=$2;", cmk_id, pid)
	if err1 != nil {
		panic(err1.Error())
	}
	var encrypted_kek string
	encrypted_key_row.Next()
	encrypted_key_row.Scan(&encrypted_kek)

	if encrypted_kek == "" {
		return ""
	}
	return encrypted_kek
}
