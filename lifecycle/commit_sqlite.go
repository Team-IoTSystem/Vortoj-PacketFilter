package lifecycle

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/gocraft/dbr"
)

const (
	LOCALPATH string = "./PacketVortoj.db"
	TABELNAME string = "packet"
)

type Packet struct {
	DeviceID        int64
	SrcMAC          string
	DstMAC          string
	SrcIP           string
	DstIP           string
	SrcPort         string
	DstPort         string
	Sequence        int64
	SYN             bool
	ACK             bool
	protocol        string
	Length          int64
	PacketTimeStanp time.Time
	DataChank       string
}

type TPacket struct {
	ID        int16  `db:"id"`
	DeviceID  string `db:"deviceid"`
	SrcMAC    string `db:"src_mac"`
	DstMAC    string `db:"dst_mac"`
	SrcIP     string `db:"src_ip"`
	DstIP     string `db:"dst_ip"`
	SrcPort   string `db:"src_port"`
	DstPort   string `db:"dst_port"`
	SYN       bool   `db:"syn"`
	ACK       bool   `db:"ack"`
	Sequence  int64  `db:"sequence"`
	Protocol  string `db:"protocol"`
	Length    int64  `db:"length"`
	DataChank []byte `db:"datachank"`
}

var dbinstance *dbr.Connection

func getDBInstance(dbtype string) (*dbr.Connection, error) {
	var err error
	if dbinstance == nil {
		if !fileExists(LOCALPATH) { //LOCALPATHに指定されたファイルチェック
			fmt.Println("create " + LOCALPATH + " file")
			// os.Create(LOCALPATH)
			d, e := sql.Open("sqlite3", LOCALPATH)
			if e != nil {
				panic(e)
			}
			createtabel := `CREATE TABLE ` + TABELNAME + ` (`
			createtabel += `"id" INTEGER PRIMARY KEY AUTOINCREMENT,`
			createtabel += ` "deviceid" TEXT,`
			createtabel += ` "src_mac" TEXT,`
			createtabel += ` "dst_mac" TEXT,`
			createtabel += ` "src_ip" TEXT,`
			createtabel += ` "dst_ip" TEXT,`
			createtabel += ` "src_port" TEXT,`
			createtabel += ` "dst_port" TEXT,`
			createtabel += ` "syn" INTEGER,`
			createtabel += ` "ack" INTEGER,`
			createtabel += ` "sequence" INTEGER,`
			createtabel += ` "protocol" TEXT,`
			createtabel += ` "length" INTEGER,`
			createtabel += ` "datachank" BLOB`
			createtabel += `)`
			_, e = d.Exec(createtabel)
			if e != nil {
				fmt.Println(e)
				panic(e)
			}
			d.Close()
			fmt.Println("created" + LOCALPATH)
		}
		dbinstance, err = dbr.Open(dbtype, LOCALPATH, nil)
	}
	return dbinstance, err
}
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
func InsertPacketData(p *TPacket) bool {
	insertpacket := p

	conn, err := getDBInstance("sqlite3")
	if err != nil {
		os.Exit(-1)
	}
	sess := conn.NewSession(nil)

	stmt := sess.InsertInto("packet").Columns(
		"deviceid",
		"src_mac",
		"dst_mac",
		"src_ip",
		"dst_ip",
		"src_port",
		"dst_port",
		"syn",
		"ack",
		"sequence",
		"protocol",
		"length",
		"datachank").Record(insertpacket)

	result, err := stmt.Exec()
	if err != nil {
		fmt.Println(err)
		return false
	} else {
		//result.RowsAffected()
		count, _ := result.RowsAffected()
		fmt.Println(count)
		return true
	}
}

// type TPacketDataDao struct{
// 	conn dbr.Connection
// 	tabel string
// }

// func TPacketDataSQLite() TPacketDataDao{
// 	return TPacketDataSQLite{
// 		conn:ConnMaster
// 		tabel:`t_primary_id`
// 	}
// }

// type PacketDataSQLite struct{}

// func NewPacketDataSQLite() PacketDataSQLite{
// 	return PacketDataSQLite{}
// }

// func (packetdata PacketDataSQLite) packetDataInsert(pcap Packet)(){
// 	var packet packet
// }
