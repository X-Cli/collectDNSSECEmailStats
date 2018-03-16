# Collect DNSSEC-related Email Stats

This tool parses Afnic OpenData list of domain names from the .fr zone file.
Then, it queries every domain name of that list that are still in the Whois
database (according to Afnic file) for DNS records related to DNSSEC and
SMTP-related policies (SPF, DKIM and DMARC).

The measurement results are stored in a SQLite3 database, and summarized using
SQL views.

## Installation

### From release

### From source

First, install the go compiler from golang.org.

Set up your GO environment

```
export GOROOT=/path/to/go/main/dir
export GOBIN=${GOROOT}/bin
export GOPATH=/path/to/a/directory/for/this/project
```

Then, download this project and its dependencies:

```
cd ${GOPATH}
go get github.com/X-Cli/collectDNSSECEmailStats
cd src/github.com/X-Cli/collectDNSSECEmailStats
go get ./...
```

Finally, compile the project:
```
go build collect.go
```

This creates the executable `${GOPATH}/src/github.com/X-Cli/collectDNSSECEmailStats/collect`.

## Perform measurements

First, you need to download the zip file from Afnic OpenData project. Navigate
to https://opendata.afnic.fr/en/ and download "option A", "A- noms de domaine
en point fr.zip".

Then, launch the measurement (Do not launch it right away; this is only an
example! Read on!):

```
./collect -file /path/to/afnic/file/you/just/downloaded -db /path/to/database/to/store/measurement/results
```

If the path to the database does not exist, the database tables and view ares
created.

The `collect` executable comes with various other options:

 - jobs: defines the number of workers that perform the measurement. The more,
   the faster, and the more chances you have to be blacklisted for harassing
some DNS servers. Since this tool is mainly I/O based, it is reasonnable to
have more workers than CPU slots; many will be on I/O wait.

 - parsec: is the number of queries per seconds that are sent by the workers.
   Same warning about the speed/blacklist risk trade-off as for jobs.

 - verbose: displays an incrementing counter every 10K domain names, to let you
   know roughly what's in the pipes.

 - resolver: defines which full-resolver will be queried. By default, Google
   Public DNS is used, but it is highly recommended to host your own resolver,
for performance reasons as well as for fair-use of Google Public DNS reasons.

## Measurement results

The author of this tool performed some measurements in the past.

Here is a list of the SQLite3 databases that are available for download:
- https://x-cli.eu/measurement_results_emails_201803.db (from AS16276, performed early March 2018)

## Querying the results

The database contains a view named `summary`, which contains an aggregated view
of domain names and whether or not they have DS records, SPF records, DMARC
records, and possibly DKIM records or not (according to RFC8020).  The SQL
requests can be combined, for instance to list domain names that have
DNSSEC-signed SPF or DKIM or DMARC records.

### Listing DNSSEC-enabled domains

```
sqlite3> SELECT * from summary where dnssec=1;
```

### Listing SPF-enabled domains

```
sqlite3> SELECT * from summary where spfrec=1;
```

### Listing DKIM-enabled domains

Listing domains that do not have DKIM according to RFC8020:

```
sqlite3> SELECT * from summary where dkimrec=0;
```

For a domain to have dkimrec set to 0, a query for `_domainkey.<domainname>`
must return an answer with rcode 3 (NXDomain). According to RFC8020, the DNS is
a tree. So if `_domainkey.<domainname>` does not exist, then there should be no
subdomain to this name. Since DKIM records are published in subdomains of
`_domainkey.<domainname>`, this is proof there are no DKIM keys for that
domain. If the rcode is not 3, then there might be DKIM records or not; there
is no way to tell, because DKIM keys are hosted in domain name containing a DNS
label that is unpredictable for us: the DKIM selector.

### Listing DMARC-enabled domains

```
sqlite3> SELECT * from summary where dmarcrec=0;
```


