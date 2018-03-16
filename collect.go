package main

import (
	"database/sql"
	"flag"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"time"
	"os"
	"fmt"
	"strings"
	"archive/zip"
	"errors"
	"encoding/csv"
	"io"
)

func doQuery(qc <-chan *dns.Msg, res chan<- *dns.Msg, parSec int, address string) {
	rsv := new(dns.Client)
	rsv.Timeout = 5 * time.Second
	rsv.UDPSize = 4096
	lastQryTime := time.Now()

	for m := range qc {
		rsv.Net = ""
		for {
			if now := time.Now(); now.Sub(lastQryTime) < time.Duration(float64(1*time.Second)/float64(parSec)) {
				time.Sleep(time.Duration(float64(1*time.Second)/float64(parSec) - float64(now.Sub(lastQryTime))))
			}
			lastQryTime = time.Now()
			r, _, err := rsv.Exchange(m, address)

			if err != nil || r == nil {
				m.Rcode = dns.RcodeServerFailure
				m.RecursionAvailable = true
				m.Response = true
				res <- m
			} else {
				if rsv.Net == "" && r.Truncated {
					rsv.Net = "tcp"
					continue
				}
				res <- r
			}
			break
		}
	}
	// Signal there are no more results from this worker
	res <- nil
}

func register(txn *sql.Tx, m *dns.Msg) error {
	var qtype string
	qname := m.Question[0].Name

	if tok := "_dmarc" ; len(qname) > len(tok) && qname[:len(tok)] == tok {
		qtype = "DMARC"
		qname = qname[len(tok)+1:]
	} else if tok := "_domainkey" ; len(qname) > len(tok) && qname[:len(tok)] == tok {
		qtype = "DKIM"
		qname = qname[len(tok)+1:]
	} else {
		qtypeInt := m.Question[0].Qtype
		if qtypeInt == dns.TypeTXT {
			qtype = "SPF"
		} else {
			qtype = dns.TypeToString[qtypeInt]
		}
	}

	sqlStmt := "INSERT INTO records(name, qtype, rcode, value) VALUES ($1, $2, $3, $4);"

	if m.Rcode != 0 || len(m.Answer) == 0 {
		_, err := txn.Exec(sqlStmt, qname, qtype, m.Rcode, sql.NullString{})
		return err
	}

	inserted := false
	for _, ans := range m.Answer {
		switch typedAns := ans.(type) {
		case *dns.DS:
			_, err := txn.Exec(sqlStmt, qname, qtype, m.Rcode, fmt.Sprintf("%d %d %d %s", typedAns.KeyTag, typedAns.Algorithm, typedAns.DigestType, typedAns.Digest))
			if err != nil {
				return err
			}
			inserted = true
		case *dns.TXT:
			value := strings.Join(typedAns.Txt, " ")
			switch qtype {
			case "DMARC":
				if tok := "v=DMARC1;" ; len(value) < len(tok) || value[:len(tok)] != tok {
					continue
				}
			case "SPF":
				if tok := "v=spf1" ; len(value) < len(tok) || value[:len(tok)] != tok {
					continue
				}
			case "DKIM":
				continue
			}
			_, err := txn.Exec(sqlStmt, qname, qtype, m.Rcode, value)
			inserted = true
			if err != nil {
				return err
			}
		}
	}

	// inserted may value false if there was an rcode==0, a qtype=="TXT" but no TXT record was correctly formated
	if !inserted {
		_, err := txn.Exec(sqlStmt, qname, qtype, m.Rcode, sql.NullString{})
		if err != nil {
			return err
		}
	}
	return nil
}

func collect(parSec int, address string, dbConn *sql.DB, res chan<- *dns.Msg, dn <-chan string) {
	var m *dns.Msg

	qc := make(chan *dns.Msg, 4)
	go doQuery(qc, res, parSec, address)

	for dom := range dn {
		// DS
		m = new(dns.Msg)
		m.SetQuestion(dom, dns.TypeDS)
		m.SetEdns0(4096, false)
		m.CheckingDisabled = true
		qc <- m

		// SPF
		m = new(dns.Msg)
		m.SetQuestion(dom, dns.TypeTXT)
		m.SetEdns0(4096, false)
		m.CheckingDisabled = true
		qc <- m

		// DKIM
		m = new(dns.Msg)
		m.SetQuestion("_domainkey."+dom, dns.TypeTXT)
		m.SetEdns0(4096, false)
		m.CheckingDisabled = true
		qc <- m

		// DMARC
		m = new(dns.Msg)
		m.SetQuestion("_dmarc."+dom, dns.TypeTXT)
		m.SetEdns0(4096, false)
		m.CheckingDisabled = true
		qc <- m
	}
	close(qc)
}

func collectInfoFor(jobCount, parSec int, address, db string, dn <-chan string) {
	dbConn, err := sql.Open("sqlite3", db)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer dbConn.Close()

	txn, err := dbConn.Begin()
	if err != nil {
		return
	}
	defer txn.Commit()

	res := make(chan *dns.Msg, 100000)
	for i := 0; i < jobCount; i++ {
		go collect(parSec, address, dbConn, res, dn)
	}

	i := 0
	doneCount := 0
	for answer := range res {
		i += 1
		if answer == nil {
			doneCount += 1
			if doneCount == jobCount {
				break
			}
		} else if err := register(txn, answer) ; err != nil {
			fmt.Println(res, err)
		}
		if i % 10000 == 0 {
			txn.Commit()
			txn, err = dbConn.Begin()
			if err != nil {
				return
			}
		}
	}
}

func createDatabase(db string) error {
	if _, err := os.Stat(db) ; err == nil {
		// file exists
		return nil
	}

	c, err := sql.Open("sqlite3", db)
	if err != nil {
		return err
	}
	defer c.Close()

	if err = c.Ping() ; err != nil {
		return err
	}

	createTableStmt := "CREATE TABLE records(name varchar(255) not null, qtype varchar(6) not null, rcode int not null, value text null);"
	_, err = c.Exec(createTableStmt)
	if err != nil {
		return err
	}

	createTableStmt = "CREATE VIEW summary_dnssec AS SELECT name, CASE WHEN rcode==0 AND qtype='DS' AND value IS NOT NULL THEN 1 ELSE 0 END dnssec FROM records WHERE qtype='DS' GROUP BY name, dnssec;"
	_, err = c.Exec(createTableStmt)
	if err != nil {
		return err
	}
	createTableStmt = "CREATE VIEW summary_spf AS SELECT name, CASE WHEN rcode==0 AND qtype='SPF' AND value IS NOT NULL THEN 1 ELSE 0 END spfrec FROM records WHERE qtype='SPF' GROUP BY name, spfrec;"
	_, err = c.Exec(createTableStmt)
	if err != nil {
		return err
	}
	createTableStmt = "CREATE VIEW summary_dkim AS SELECT name, CASE WHEN rcode==3 AND qtype='DKIM' THEN 0 ELSE 1 END dkimrec FROM records WHERE qtype='DKIM' GROUP BY name, dkimrec;"
	_, err = c.Exec(createTableStmt)
	if err != nil {
		return err
	}
	createTableStmt = "CREATE VIEW summary_dmarc AS SELECT name, CASE WHEN rcode==0 AND qtype='DMARC' AND value IS NOT NULL THEN 1 ELSE 0 END dmarcrec FROM records WHERE qtype='DMARC' GROUP BY name, dmarcrec;"
	_, err = c.Exec(createTableStmt)
	if err != nil {
		return err
	}
	createTableStmt = "CREATE VIEW summary AS SELECT summary_dnssec.name, dnssec, spfrec, dkimrec, dmarcrec FROM summary_dnssec inner join summary_spf on summary_dnssec.name == summary_spf.name inner join summary_dkim on summary_dnssec.name == summary_dkim.name inner join summary_dmarc on summary_dnssec.name == summary_dmarc.name;"
	_, err = c.Exec(createTableStmt)
	if err != nil {
		return err
	}

	return nil
}

func parseOpenData(fn string, dn chan<- string, verbose bool) error {
	// Open zip file
	zipRd, err := zip.OpenReader(fn)
	if err != nil {
		close(dn)
		return err
	}
	// Verify there is only one file in the zip file (the expected CSV)
	if len(zipRd.Reader.File) != 1 {
		close(dn)
		return errors.New("parseOpenData: unexpected format for Afnic zip file: should contain only one CSV file")
	}
	// Open the CSV file
	f, err := zipRd.Reader.File[0].Open()
	if err != nil {
		close(dn)
		return err
	}

	csvRd := csv.NewReader(f)
	csvRd.Comma = ';'

	// drop first line which contains the CSV headers
	if _, err := csvRd.Read() ; err != nil {
		close(dn)
		return errors.New("parseOpenData: empty Afnic zip file")
	}

	go func() {
		i := 0
		for {
			record, err := csvRd.Read()
			if err != nil {
				if err == io.EOF {
					break
				}
				continue
			}
			if len(record[11]) == 0 {
				dn <- dns.Fqdn(record[0])
				i += 1
				if i % 10000 == 0 {
					fmt.Println(i)
				}
			}
		}
		close(dn)
	}()
	return nil

}

func main() {
	var err error

	fn := flag.String("file", "", "Path to Afnic Zip file")
	jobCnt := flag.Int("jobs", 10, "Number of concurrent jobs")
	parSec := flag.Int("parsec", 1, "Number of queries per seconds sent by a worker")
	address := flag.String("resolver", "8.8.8.8:53", "Resolver to query")
	db := flag.String("db", "", "Filename for the sqlite3 database")
	verbose := flag.Bool("verbose", false, "Display a counter of the number of queried domains")

	flag.Parse()

	if len(*fn) == 0 {
		panic("Missing parameter: file")
	}
	if len(*db) == 0 {
		panic("Missing parameter: db")
	}

	if err = createDatabase(*db) ; err != nil {
		panic(err)
	}

	dn := make(chan string, 1000)

	if err = parseOpenData(*fn, dn, *verbose); err != nil {
		panic(err)
	}

	collectInfoFor(*jobCnt, *parSec, *address, *db, dn)
}
