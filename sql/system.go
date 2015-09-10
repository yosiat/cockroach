// Copyright 2015 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License. See the AUTHORS file
// for names of contributors.
//
// Author: Marc Berhault (marc@cockroachlabs.com)

package sql

import (
	"github.com/cockroachdb/cockroach/client"
	"github.com/cockroachdb/cockroach/config"
	"github.com/cockroachdb/cockroach/keys"
	"github.com/cockroachdb/cockroach/proto"
	"github.com/cockroachdb/cockroach/security"
	"github.com/cockroachdb/cockroach/sql/parser"
	"github.com/cockroachdb/cockroach/sql/privilege"
	"github.com/cockroachdb/cockroach/util"
	"github.com/cockroachdb/cockroach/util/encoding"
	"github.com/cockroachdb/cockroach/util/log"
)

const (
	// MaxReservedDescID is the maximum reserved descriptor ID.
	// All objects with ID <= MaxReservedDescID are system object
	// with special rules.
	MaxReservedDescID ID = keys.MaxReservedDescID
	// RootNamespaceID is the ID of the root namespace.
	RootNamespaceID ID = 0

	// System IDs should remain <= MaxReservedDescID.
	systemDatabaseID  ID = 1
	namespaceTableID  ID = 2
	descriptorTableID ID = 3
	usersTableID      ID = 4
	zonesTableID      ID = 5

	// sql CREATE commands and full schema for each system table.
	namespaceTableSchema = `
CREATE TABLE system.namespace (
  parentID INT,
  name     CHAR,
  id       INT,
  PRIMARY KEY (parentID, name)
);`

	descriptorTableSchema = `
CREATE TABLE system.descriptor (
  id         INT PRIMARY KEY,
  descriptor BLOB
);`

	usersTableSchema = `
CREATE TABLE system.users (
  username       CHAR PRIMARY KEY,
  hashedPassword BLOB
);`

	// Zone settings per DB/Table.
	zonesTableSchema = `
CREATE TABLE system.zones (
  id     INT PRIMARY KEY,
  config BLOB
);`
)

var (
	// SystemDB is the descriptor for the system database.
	SystemDB = DatabaseDescriptor{
		Name: "system",
		ID:   systemDatabaseID,
		// Assign max privileges to root user.
		Privileges: NewPrivilegeDescriptor(security.RootUser,
			SystemAllowedPrivileges[systemDatabaseID]),
	}

	// NamespaceTable is the descriptor for the namespace table.
	NamespaceTable = createSystemTable(namespaceTableID, namespaceTableSchema)

	// DescriptorTable is the descriptor for the descriptor table.
	DescriptorTable = createSystemTable(descriptorTableID, descriptorTableSchema)

	// UsersTable is the descriptor for the users table.
	UsersTable = createSystemTable(usersTableID, usersTableSchema)

	// ZonesTable is the descriptor for the zones table.
	ZonesTable = createSystemTable(zonesTableID, zonesTableSchema)

	// SystemAllowedPrivileges describes the privileges allowed for each
	// system object. No user may have more than those privileges, and
	// the root user must have exactly those privileges.
	// CREATE|DROP|ALL should always be denied.
	SystemAllowedPrivileges = map[ID]privilege.List{
		systemDatabaseID:  privilege.ReadData,
		namespaceTableID:  privilege.ReadData,
		descriptorTableID: privilege.ReadData,
		usersTableID:      privilege.ReadWriteData,
		zonesTableID:      privilege.ReadWriteData,
	}

	// Map of ID -> table descriptor.
	tableDescriptorsByID = map[ID]TableDescriptor{
		namespaceTableID:  NamespaceTable,
		descriptorTableID: DescriptorTable,
		usersTableID:      UsersTable,
		zonesTableID:      ZonesTable,
	}

	// NumUsedSystemIDs is only used in tests that need to know the
	// number of system objects created at initialization.
	// It gets automatically set to "number of created system tables"
	// + 1 (for system database).
	NumUsedSystemIDs = 1
)

func createSystemTable(id ID, cmd string) TableDescriptor {
	stmts, err := parser.ParseTraditional(cmd)
	if err != nil {
		log.Fatal(err)
	}

	desc, err := makeTableDesc(stmts[0].(*parser.CreateTable))
	if err != nil {
		log.Fatal(err)
	}

	// Assign max privileges to root user.
	desc.Privileges = NewPrivilegeDescriptor(security.RootUser,
		SystemAllowedPrivileges[id])

	desc.ID = id
	if err := desc.AllocateIDs(); err != nil {
		log.Fatal(err)
	}

	NumUsedSystemIDs++
	return desc
}

// GetInitialSystemValues returns a list of key/value pairs.
// They are written at cluster bootstrap time (see storage/node.go:BootstrapCLuster).
func GetInitialSystemValues() []proto.KeyValue {
	systemData := []struct {
		parentID ID
		desc     descriptorProto
	}{
		{RootNamespaceID, &SystemDB},
		{SystemDB.ID, &NamespaceTable},
		{SystemDB.ID, &DescriptorTable},
		{SystemDB.ID, &UsersTable},
		{SystemDB.ID, &ZonesTable},
	}

	// Initial kv pairs:
	// - ID generator
	// - 2 per table/database
	numEntries := 1 + len(systemData)*2
	ret := make([]proto.KeyValue, numEntries, numEntries)
	i := 0

	// Descriptor ID generator.
	value := proto.Value{}
	value.SetInteger(int64(MaxReservedDescID + 1))
	ret[i] = proto.KeyValue{
		Key:   keys.DescIDGenerator,
		Value: value,
	}
	i++

	// System database and tables.
	for _, d := range systemData {
		value = proto.Value{}
		value.SetInteger(int64(d.desc.GetID()))
		ret[i] = proto.KeyValue{
			Key:   MakeNameMetadataKey(d.parentID, d.desc.GetName()),
			Value: value,
		}
		i++

		value = proto.Value{}
		if err := value.SetProto(d.desc); err != nil {
			log.Fatalf("could not marshal %v", d.desc)
		}
		ret[i] = proto.KeyValue{
			Key:   MakeDescMetadataKey(d.desc.GetID()),
			Value: value,
		}
		i++
	}

	return ret
}

// IsSystemID returns true if this ID is reserved for system objects.
func IsSystemID(id ID) bool {
	return id > 0 && id <= MaxReservedDescID
}

// makeScanPlan takes a table ID and builds a scanNode for it.
// TODO(peter): we need a cleaner way of calling this.
func makeScanPlan(id ID) (*scanNode, error) {
	var err error
	desc, ok := tableDescriptorsByID[id]
	if !ok {
		return nil, util.Errorf("no descriptor found for system table with ID %d", id)
	}
	plan := &scanNode{}
	plan.desc = &desc
	plan.index = &plan.desc.PrimaryIndex
	plan.visibleCols = plan.desc.Columns
	plan.addRender(parser.SelectExpr{Expr: parser.StarExpr()})
	plan.initOrdering()
	if plan.valTypes, err = makeKeyVals(plan.desc, plan.columnIDs); err != nil {
		return nil, err
	}
	plan.vals = make([]parser.Datum, len(plan.valTypes))
	plan.colKind = make(colKindMap, len(plan.desc.Columns))
	for _, col := range plan.desc.Columns {
		plan.colKind[col.ID] = col.Type.Kind
	}
	return plan, plan.Err()
}

var scanPlans = map[ID]*scanNode{}

func getScanPlanFor(id ID) (*scanNode, error) {
	if s, ok := scanPlans[id]; ok {
		// Reset KV stuff.
		s.kvIndex = 0
		s.kvs = []client.KeyValue{}
		s.err = nil
		return s, nil
	}

	s, err := makeScanPlan(id)
	if err != nil {
		return nil, err
	}
	scanPlans[id] = s
	return s, nil
}

func scanAll(plan *scanNode) (parser.DTuple, error) {
	var rows parser.DTuple
	for plan.Next() {
		appendValuesCopy(&rows, plan.Values())
	}
	return rows, plan.Err()
}

// BuildSystemConfig takes a full system span as a sorted list of
// key/value pairs and returns a SystemConfig.
func BuildSystemConfig(kvs []proto.KeyValue) (*config.SystemConfig, error) {
	namespacePlan, err := getScanPlanFor(namespaceTableID)
	if err != nil {
		return nil, err
	}
	descriptorPlan, err := getScanPlanFor(descriptorTableID)
	if err != nil {
		return nil, err
	}
	// TODO(marc): gossip users and consume.
	zonesPlan, err := getScanPlanFor(zonesTableID)
	if err != nil {
		return nil, err
	}

	ignoredPrefixLength := len(keys.TableDataPrefix)
	// Iterate over all proto.KeyValue pairs and add them to the
	// proper scanPlan based on table ID.
	for _, kv := range kvs {
		v := client.KeyValue{
			Key:   kv.Key,
			Value: kv.Value.Bytes,
			// TODO(marc): I don't think sql makes use of the timestamp.
			Timestamp: kv.Value.Timestamp.GoTime(),
		}
		_, id := encoding.DecodeUvarint(kv.Key[ignoredPrefixLength:])
		switch ID(id) {
		case namespaceTableID:
			namespacePlan.kvs = append(namespacePlan.kvs, v)
		case descriptorTableID:
			descriptorPlan.kvs = append(descriptorPlan.kvs, v)
		case zonesTableID:
			zonesPlan.kvs = append(zonesPlan.kvs, v)
		}
	}

	systemConfig := &config.SystemConfig{
		DatabaseNames: map[string]uint32{},
		Databases:     map[uint32]*config.DatabaseRegistry{},
		Descriptors:   map[uint32][]byte{},
		Zones:         []config.ZoneDescriptor{},
	}

	if err := processNamespaceTable(systemConfig, namespacePlan); err != nil {
		return nil, err
	}
	if err := processDescriptorTable(systemConfig, descriptorPlan); err != nil {
		return nil, err
	}
	if err := processZonesTable(systemConfig, zonesPlan); err != nil {
		return nil, err
	}

	systemConfig.Values = kvs
	return systemConfig, nil
}

// processNamespaceTable iterates through the entries in the namespace
// table and populates the database and tables registries.
// TODO(marc): we do not check the datum type conversions or config
// validity. If is not as expected, things are horrible. We should
// really strictly validate things before.
func processNamespaceTable(cfg *config.SystemConfig, plan *scanNode) error {
	results, err := scanAll(plan)
	if err != nil {
		return err
	}
	for _, row := range results {
		tuple := row.(parser.DTuple)
		parentID := uint32(tuple[0].(parser.DInt))
		name := string(tuple[1].(parser.DString))
		id := uint32(tuple[2].(parser.DInt))
		// TODO(marc): should we check relationships here? We're in deep trouble
		// if they're bad.
		if ID(parentID) == RootNamespaceID {
			// This is a database.
			cfg.DatabaseNames[name] = id
			cfg.Databases[id] = &config.DatabaseRegistry{Name: name, Tables: map[string]uint32{}}
		} else {
			cfg.Databases[parentID].Tables[name] = id
		}
	}
	return nil
}

// processDescriptorTable iterates through the entries in the descriptor
// table and populates the database map.
func processDescriptorTable(cfg *config.SystemConfig, plan *scanNode) error {
	results, err := scanAll(plan)
	if err != nil {
		return err
	}
	for _, row := range results {
		tuple := row.(parser.DTuple)
		id := uint32(tuple[0].(parser.DInt))
		blob := []byte(tuple[1].(parser.DString))
		cfg.Descriptors[id] = blob
	}
	return nil
}

// processZonesTable iterates through the entries in the zones table
// and populates the zone config.
// NOTE: this depends on the database registry built in processNamespaceTable.
// TODO(marc): if two tables with sequential IDs have the same zone config
// (either because their DB has one, or because they both have the same),
// we don't collapse the two spans into one. Maybe we should.
// However, we may decide to split at all table boundaries.
// TODO(marc): should we skip system tables here or rely on the
// config writer to avoid those?
func processZonesTable(cfg *config.SystemConfig, plan *scanNode) error {
	results, err := scanAll(plan)
	if err != nil {
		return err
	}

	zoneDescForTableID := func(id uint32, blob []byte) config.ZoneDescriptor {
		return config.ZoneDescriptor{
			Start: keys.MakeTablePrefix(id),
			End:   keys.MakeTablePrefix(id + 1),
			Cfg:   blob,
		}
	}

	// We have at least len(results) zones. We may have more
	// if some of those are for databases.
	zones := make([]config.ZoneDescriptor, 0, len(results))
	for _, row := range results {
		tuple := row.(parser.DTuple)
		id := uint32(tuple[0].(parser.DInt))
		blob := []byte(tuple[1].(parser.DString))
		if registry, ok := cfg.Databases[id]; ok {
			// This is a database, add all its tables.
			for _, tableID := range registry.Tables {
				zones = append(zones, zoneDescForTableID(tableID, blob))
			}
		} else {
			zones = append(zones, zoneDescForTableID(id, blob))
		}
	}

	// Sort the zone configs.
	// sort.Sort(zones)
	cfg.Zones = zones

	return nil
}
