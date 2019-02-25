package shortner

import "github.com/go-sql-driver/mysql"

type Config struct {
	MySQLConfig mysql.Config
}

func NewServer(cfg Config) (Server, error) {

}
