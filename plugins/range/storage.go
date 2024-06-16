// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type leaseDB struct {
	f *os.File
}

func loadDB(path string) (*leaseDB, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open database (%T): %w", err, err)
	}
	return &leaseDB{f}, nil
}

// loadRecords loads the DHCPv6/v4 Records global map with records stored on
// the specified file. The records have to be one per line, a mac address and an
// IP address.
func loadRecords(db *leaseDB) (map[string]*Record, error) {
	scanner := bufio.NewScanner(db.f)
	var (
		mac, ip, hostname string
		expiry            int
		records           = make(map[string]*Record)
		hwaddr            net.HardwareAddr
		err               error
	)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ",")
		mac, ip, hostname = fields[0], fields[1], fields[3]
		expiry, err = strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("couldn't parse expiry: %s", fields[2])
		}
		hwaddr, err = net.ParseMAC(mac)
		if err != nil {
			return nil, fmt.Errorf("malformed hardware address: %s", mac)
		}
		ipaddr := net.ParseIP(ip)
		if ipaddr.To4() == nil {
			return nil, fmt.Errorf("expected an IPv4 address, got: %v", ipaddr)
		}
		records[hwaddr.String()] = &Record{IP: ipaddr, expires: expiry, hostname: hostname}
	}
	return records, nil
}

// saveIPAddress writes out a lease to storage
func (p *PluginState) saveIPAddress(mac net.HardwareAddr, record *Record) error {
	_, err := p.leasedb.f.WriteString(fmt.Sprintf("%s,%s,%d,%s\n",
		mac.String(), record.IP.String(), record.expires, record.hostname))
	if err != nil {
		return fmt.Errorf("record insert/update failed: %w", err)
	}
	return nil
}

// registerBackingDB installs a database connection string as the backing store for leases
func (p *PluginState) registerBackingDB(filename string) error {
	if p.leasedb != nil {
		return errors.New("cannot swap out a lease database while running")
	}
	// We never close this, but that's ok because plugins are never stopped/unregistered
	newLeaseDB, err := loadDB(filename)
	if err != nil {
		return fmt.Errorf("failed to open lease database %s: %w", filename, err)
	}
	p.leasedb = newLeaseDB
	return nil
}
