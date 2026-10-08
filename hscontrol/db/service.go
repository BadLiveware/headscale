package db

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

var errServiceVIPsMissing = errors.New("service has no virtual IP address")

// gormDialectSQLite is what [gorm.DB.Name] returns for SQLite.
const gormDialectSQLite = "sqlite"

// servicesDDLSQLite matches schema.sql byte for byte; the squibble digest
// of the SQLite schema is the source of truth.
const servicesDDLSQLite = `CREATE TABLE services(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text NOT NULL,
  ipv4 text,
  ipv6 text,

  created_at datetime
)`

const servicesDDLPostgres = `CREATE TABLE services(
  id bigserial PRIMARY KEY,
  name text NOT NULL,
  ipv4 text,
  ipv6 text,

  created_at timestamptz
)`

const servicesNameIndex = `CREATE UNIQUE INDEX idx_services_name ON services(name)`

// ensureServicesTable creates the services table, which holds the virtual
// IP addresses of Tailscale Services. Explicit DDL for both dialects.
func ensureServicesTable(tx *gorm.DB) error {
	if tx.Migrator().HasTable(&types.Service{}) {
		return nil
	}

	ddl := servicesDDLSQLite
	if tx.Name() != gormDialectSQLite {
		ddl = servicesDDLPostgres
	}

	err := tx.Exec(ddl).Error
	if err != nil {
		return fmt.Errorf("creating services table: %w", err)
	}

	err = tx.Exec(servicesNameIndex).Error
	if err != nil {
		return fmt.Errorf("creating services name index: %w", err)
	}

	return nil
}

// ListServices returns every service that has virtual IP addresses.
func (hsdb *HSDatabase) ListServices() ([]types.Service, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]types.Service, error) {
		var services []types.Service

		err := rx.Order("id").Find(&services).Error
		if err != nil {
			return nil, fmt.Errorf("listing services: %w", err)
		}

		return services, nil
	})
}

// CreateServices allocates virtual IP addresses for each named service and
// stores them. The caller passes only names without a row. Addresses come
// from the node allocator, so a VIP never collides with a node address.
func (hsdb *HSDatabase) CreateServices(alloc *IPAllocator, names []string) ([]types.Service, error) {
	if len(names) == 0 {
		return nil, nil
	}

	return Write(hsdb.DB, func(tx *gorm.DB) ([]types.Service, error) {
		created := make([]types.Service, 0, len(names))

		for _, name := range names {
			ipv4, ipv6, err := alloc.Next()
			if err != nil {
				return nil, fmt.Errorf("allocating addresses for %q: %w", name, err)
			}

			if ipv4 == nil && ipv6 == nil {
				return nil, fmt.Errorf("%w: %q", errServiceVIPsMissing, name)
			}

			svc := types.Service{Name: name, IPv4: ipv4, IPv6: ipv6}

			err = tx.Create(&svc).Error
			if err != nil {
				alloc.FreeIPs(addrsOf(ipv4, ipv6))

				return nil, fmt.Errorf("storing service %q: %w", name, err)
			}

			created = append(created, svc)
		}

		return created, nil
	})
}

func addrsOf(addrs ...*netip.Addr) []netip.Addr {
	var out []netip.Addr

	for _, a := range addrs {
		if a != nil {
			out = append(out, *a)
		}
	}

	return out
}
