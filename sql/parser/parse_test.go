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
// Author: Peter Mattis (peter@cockroachlabs.com)

package parser

import (
	"reflect"
	"testing"

	"github.com/cockroachdb/cockroach/testutils"
	_ "github.com/cockroachdb/cockroach/util/log" // for flags
)

// TestParse verifies that we can parse the supplied SQL and regenerate the SQL
// string from the syntax tree.
func TestParse(t *testing.T) {
	testData := []struct {
		sql string
	}{
		{``},
		{`VALUES ("")`},

		{`BEGIN TRANSACTION`},
		{`BEGIN TRANSACTION ISOLATION LEVEL SNAPSHOT`},
		{`BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE`},
		{`COMMIT TRANSACTION`},
		{`ROLLBACK TRANSACTION`},

		{`CREATE DATABASE a`},
		{`CREATE DATABASE IF NOT EXISTS a`},

		{`CREATE INDEX a ON b (c)`},
		{`CREATE INDEX a ON b.c (d)`},
		{`CREATE INDEX ON a (b)`},
		{`CREATE INDEX ON a (b) STORING (c)`},
		{`CREATE UNIQUE INDEX a ON b (c)`},
		{`CREATE UNIQUE INDEX a ON b (c) STORING (d)`},
		{`CREATE UNIQUE INDEX a ON b.c (d)`},

		{`CREATE TABLE a ()`},
		{`CREATE TABLE a (b INT)`},
		{`CREATE TABLE a (b INT, c INT)`},
		{`CREATE TABLE a (b CHAR)`},
		{`CREATE TABLE a (b CHAR(3))`},
		{`CREATE TABLE a (b FLOAT)`},
		{`CREATE TABLE a (b INT NULL)`},
		{`CREATE TABLE a (b INT NOT NULL)`},
		{`CREATE TABLE a (b INT PRIMARY KEY)`},
		{`CREATE TABLE a (b INT UNIQUE)`},
		{`CREATE TABLE a (b INT NULL PRIMARY KEY)`},
		// "0" lost quotes previously.
		{`CREATE TABLE a (b INT, c TEXT, PRIMARY KEY (b, c, "0"))`},
		{`CREATE TABLE a (b INT, c TEXT, INDEX (b, c))`},
		{`CREATE TABLE a (b INT, c TEXT, INDEX d (b, c))`},
		{`CREATE TABLE a (b INT, c TEXT, CONSTRAINT d UNIQUE (b, c))`},
		{`CREATE TABLE a (b INT, UNIQUE (b))`},
		{`CREATE TABLE a (b INT, UNIQUE (b) STORING (c))`},
		{`CREATE TABLE a (b INT, INDEX (b))`},
		{`CREATE TABLE a (b INT, INDEX (b) STORING (c))`},
		{`CREATE TABLE a.b (b INT)`},
		{`CREATE TABLE IF NOT EXISTS a (b INT)`},

		{`DELETE FROM a`},
		{`DELETE FROM a.b`},
		{`DELETE FROM a WHERE a = b`},

		{`DROP DATABASE a`},
		{`DROP DATABASE IF EXISTS a`},
		{`DROP TABLE a`},
		{`DROP TABLE a.b`},
		{`DROP TABLE a, b`},
		{`DROP TABLE IF EXISTS a`},

		{`EXPLAIN SELECT 1`},
		{`EXPLAIN (DEBUG) SELECT 1`},
		{`EXPLAIN (A, B, C) SELECT 1`},

		{`SHOW BARFOO`},
		{`SHOW DATABASE`},
		{`SHOW SYNTAX`},

		{`SHOW DATABASES`},
		{`SHOW TABLES`},
		{`SHOW TABLES FROM a`},
		{`SHOW TABLES FROM a.b.c`},
		{`SHOW COLUMNS FROM a`},
		{`SHOW COLUMNS FROM a.b.c`},
		{`SHOW INDEX FROM a`},
		{`SHOW INDEX FROM a.b.c`},
		{`SHOW TABLES FROM a; SHOW COLUMNS FROM b`},

		// Tables are the default, but can also be specified with
		// GRANT x ON TABLE y. However, the stringer does not output TABLE.
		{`SHOW GRANTS`},
		{`SHOW GRANTS ON foo`},
		{`SHOW GRANTS ON foo, db.foo`},
		{`SHOW GRANTS ON DATABASE foo, bar`},
		{`SHOW GRANTS ON DATABASE foo FOR bar`},
		{`SHOW GRANTS FOR bar, baz`},

		{`SHOW TRANSACTION ISOLATION LEVEL`},

		// Tables are the default, but can also be specified with
		// GRANT x ON TABLE y. However, the stringer does not output TABLE.
		{`GRANT SELECT ON foo TO root`},
		{`GRANT SELECT, DELETE, UPDATE ON foo, db.foo TO root, bar`},
		{`GRANT DROP ON DATABASE foo TO root`},
		{`GRANT ALL ON DATABASE foo TO root, test`},
		{`GRANT SELECT, INSERT ON DATABASE bar TO foo, bar, baz`},
		{`GRANT SELECT, INSERT ON DATABASE db1, db2 TO foo, bar, baz`},
		{`GRANT SELECT, INSERT ON DATABASE db1, db2 TO "test-user"`},

		// Tables are the default, but can also be specified with
		// REVOKE x ON TABLE y. However, the stringer does not output TABLE.
		{`REVOKE SELECT ON foo FROM root`},
		{`REVOKE UPDATE, DELETE ON foo, db.foo FROM root, bar`},
		{`REVOKE INSERT ON DATABASE foo FROM root`},
		{`REVOKE ALL ON DATABASE foo FROM root, test`},
		{`REVOKE SELECT, INSERT ON DATABASE bar FROM foo, bar, baz`},
		{`REVOKE SELECT, INSERT ON DATABASE db1, db2 FROM foo, bar, baz`},

		{`INSERT INTO a VALUES (1)`},
		{`INSERT INTO a.b VALUES (1)`},
		{`INSERT INTO a VALUES (1, 2)`},
		{`INSERT INTO a VALUES (1, 2), (3, 4)`},
		{`INSERT INTO a VALUES (a + 1, 2 * 3)`},
		{`INSERT INTO a(a, b) VALUES (1, 2)`},
		{`INSERT INTO a(a, a.b) VALUES (1, 2)`},
		{`INSERT INTO a SELECT b, c FROM d`},
		{`INSERT INTO a DEFAULT VALUES`},

		{`SELECT 1 + 1`},
		{`SELECT - - 5`},
		{`SELECT - 1`},
		{`SELECT + 1`},
		{`SELECT .1`},
		{`SELECT 1.2e1`},
		{`SELECT 1.2e+1`},
		{`SELECT 1.2e-1`},
		{`SELECT true AND false`},
		{`SELECT true AND NULL`},
		{`SELECT true = false`},
		{`SELECT (true = false)`},
		{`SELECT (SELECT 1)`},
		{`SELECT ((SELECT 1))`},
		{`SELECT ((((VALUES (1)))))`},
		{`SELECT EXISTS (SELECT 1)`},
		{`SELECT (VALUES (1))`},
		{`SELECT (1, 2, 3)`},
		{`SELECT (ROW(1, 2, 3))`},
		{`SELECT (ROW())`},
		{`SELECT (TABLE a)`},

		{`SELECT FROM t`},
		{`SELECT 1 FROM t`},
		{`SELECT 1, 2 FROM t`},
		{`SELECT * FROM t`},
		{`SELECT "*" FROM t`},
		{`SELECT a, b FROM t`},
		{`SELECT a AS b FROM t`},
		{`SELECT a.* FROM t`},
		{`SELECT a = b FROM t`},
		{`SELECT $1 FROM t`},
		{`SELECT $1, $2 FROM t`},
		{`SELECT NULL FROM t`},
		{`SELECT 0.1 FROM t`},
		{`SELECT a FROM t`},
		{`SELECT a.b FROM t`},
		{`SELECT a.b.* FROM t`},
		{`SELECT a.b[1] FROM t`},
		{`SELECT a.b[1 + 1:4][3] FROM t`},
		{`SELECT 'a' FROM t`},
		{`SELECT 'a' FROM t@bar`},

		{`SELECT 'a' AS "12345"`},
		{`SELECT 'a' AS clnm`},

		// Escaping may change since the scanning process loses information
		// (you can write e'\'' or ''''), but these are the idempotent cases.
		// Generally, anything that needs to escape plus \ and ' leads to an
		// escaped string.
		{`SELECT e'a\'a' FROM t`},
		{`SELECT e'a\\\\na' FROM t`},
		{`SELECT e'\\\\n' FROM t`},
		{`SELECT "a""a" FROM t`},
		{`SELECT a FROM "t\n"`}, // no escaping in sql identifiers
		{`SELECT a FROM "t"""`}, // no escaping in sql identifiers

		{`SELECT "FROM" FROM t`},
		{`SELECT CAST(1 AS TEXT)`},
		{`SELECT FROM t AS bar`},
		{`SELECT FROM (SELECT 1 FROM t)`},
		{`SELECT FROM (SELECT 1 FROM t) AS bar`},
		{`SELECT FROM t1, t2`},
		{`SELECT FROM t AS t1`},
		{`SELECT FROM s.t`},

		{`SELECT DISTINCT 1 FROM t`},
		{`SELECT COUNT(DISTINCT a) FROM t`},

		{`SELECT FROM t WHERE b = - 2`},
		{`SELECT FROM t WHERE a = b`},
		{`SELECT FROM t WHERE a = b AND a = c`},
		{`SELECT FROM t WHERE a = b OR a = c`},
		{`SELECT FROM t WHERE NOT a = b`},
		{`SELECT FROM t WHERE EXISTS (SELECT 1 FROM t)`},
		{`SELECT FROM t WHERE NOT (a = b)`},
		{`SELECT FROM t WHERE NOT true`},
		{`SELECT FROM t WHERE NOT false`},
		{`SELECT FROM t WHERE a IN (b)`},
		{`SELECT FROM t WHERE a IN (b, c)`},
		{`SELECT FROM t WHERE a IN (SELECT FROM t)`},
		{`SELECT FROM t WHERE a NOT IN (b, c)`},
		{`SELECT FROM t WHERE a LIKE b`},
		{`SELECT FROM t WHERE a NOT LIKE b`},
		{`SELECT FROM t WHERE a SIMILAR TO b`},
		{`SELECT FROM t WHERE a NOT SIMILAR TO b`},
		{`SELECT FROM t WHERE a BETWEEN b AND c`},
		{`SELECT FROM t WHERE a NOT BETWEEN b AND c`},
		{`SELECT FROM t WHERE a IS NULL`},
		{`SELECT FROM t WHERE a IS NOT NULL`},
		{`SELECT FROM t WHERE a IS TRUE`},
		{`SELECT FROM t WHERE a IS NOT TRUE`},
		{`SELECT FROM t WHERE a IS FALSE`},
		{`SELECT FROM t WHERE a IS NOT FALSE`},
		{`SELECT FROM t WHERE a IS UNKNOWN`},
		{`SELECT FROM t WHERE a IS NOT UNKNOWN`},
		{`SELECT FROM t WHERE a IS OF (INT)`},
		{`SELECT FROM t WHERE a IS NOT OF (FLOAT, STRING)`},
		{`SELECT FROM t WHERE a IS DISTINCT FROM b`},
		{`SELECT FROM t WHERE a IS NOT DISTINCT FROM b`},
		{`SELECT FROM t WHERE a < b`},
		{`SELECT FROM t WHERE a <= b`},
		{`SELECT FROM t WHERE a >= b`},
		{`SELECT FROM t WHERE a != b`},
		{`SELECT FROM t WHERE a = (SELECT a FROM t)`},
		{`SELECT FROM t WHERE a = (b)`},
		{`SELECT FROM t WHERE a = b & c`},
		{`SELECT FROM t WHERE a = b | c`},
		{`SELECT FROM t WHERE a = b ^ c`},
		{`SELECT FROM t WHERE a = b + c`},
		{`SELECT FROM t WHERE a = b - c`},
		{`SELECT FROM t WHERE a = b * c`},
		{`SELECT FROM t WHERE a = b / c`},
		{`SELECT FROM t WHERE a = b % c`},
		{`SELECT FROM t WHERE a = b || c`},
		{`SELECT FROM t WHERE a = + b`},
		{`SELECT FROM t WHERE a = - b`},
		{`SELECT FROM t WHERE a = ~ b`},
		{`SELECT FROM t WHERE CASE WHEN a = b THEN c END`},
		{`SELECT FROM t WHERE CASE WHEN a = b THEN c ELSE d END`},
		{`SELECT FROM t WHERE CASE WHEN a = b THEN c WHEN b = d THEN d ELSE d END`},
		{`SELECT FROM t WHERE CASE aa WHEN a = b THEN c END`},
		{`SELECT FROM t WHERE a = B()`},
		{`SELECT FROM t WHERE a = B(c)`},
		{`SELECT FROM t WHERE a = B(c, d)`},
		{`SELECT FROM t WHERE a = COUNT(*)`},
		{`SELECT (a.b) FROM t WHERE (b.c) = 2`},

		{`SELECT FROM t ORDER BY a`},
		{`SELECT FROM t ORDER BY a ASC`},
		{`SELECT FROM t ORDER BY a DESC`},

		{`SELECT FROM t HAVING a = b`},

		{`SELECT FROM t UNION SELECT 1 FROM t`},
		{`SELECT FROM t UNION SELECT 1 FROM t UNION SELECT 1 FROM t`},
		{`SELECT FROM t EXCEPT SELECT 1 FROM t`},
		{`SELECT FROM t INTERSECT SELECT 1 FROM t`},

		{`SELECT FROM t1 JOIN t2 ON a = b`},
		{`SELECT FROM t1 JOIN t2 USING (a)`},
		{`SELECT FROM t1 LEFT JOIN t2 ON a = b`},
		{`SELECT FROM t1 RIGHT JOIN t2 ON a = b`},
		{`SELECT FROM t1 INNER JOIN t2 ON a = b`},
		{`SELECT FROM t1 CROSS JOIN t2`},
		{`SELECT FROM t1 NATURAL JOIN t2`},
		{`SELECT FROM t1 INNER JOIN t2 USING (a)`},
		{`SELECT FROM t1 FULL JOIN t2 USING (a)`},

		{`SELECT FROM t LIMIT a`},
		{`SELECT FROM t OFFSET b`},
		{`SELECT FROM t LIMIT a OFFSET b`},

		{`SET a = 3`},
		{`SET a = 3, 4`},
		{`SET a = '3'`},
		{`SET a = 3.0`},
		{`SET a = $1`},
		{`SET TRANSACTION ISOLATION LEVEL SNAPSHOT`},
		{`SET TRANSACTION ISOLATION LEVEL SERIALIZABLE`},

		// TODO(pmattis): Is this a postgres extension?
		{`TABLE a`}, // Shorthand for: SELECT * FROM a

		{`TRUNCATE TABLE a`},
		{`TRUNCATE TABLE a, b.c`},

		{`UPDATE a SET b = 3`},
		{`UPDATE a.b SET b = 3`},
		{`UPDATE a SET b.c = 3`},
		{`UPDATE a SET b = 3, c = 4`},
		{`UPDATE a SET b = 3 + 4`},
		{`UPDATE a SET (b, c) = (3, 4)`},
		{`UPDATE a SET (b, c) = (SELECT 3, 4)`},
		{`UPDATE a SET b = 3 WHERE a = b`},
		{`UPDATE T AS "0" SET K = ''`},                 // "0" lost its quotes
		{`SELECT * FROM "0" JOIN "0" USING (id, "0")`}, // last "0" lost its quotes.

		{`ALTER DATABASE a RENAME TO b`},
		{`ALTER TABLE a RENAME TO b`},
		{`ALTER TABLE IF EXISTS a RENAME TO b`},
		{`ALTER INDEX a RENAME TO b`},
		{`ALTER INDEX IF EXISTS a RENAME TO b`},
		{`ALTER TABLE a RENAME COLUMN c1 TO c2`},
		{`ALTER TABLE IF EXISTS a RENAME COLUMN c1 TO c2`},

		{`ALTER TABLE a ADD b INT, ADD CONSTRAINT a_idx UNIQUE (a)`},
		{`ALTER TABLE a ADD IF NOT EXISTS b INT, ADD CONSTRAINT a_idx UNIQUE (a)`},
		{`ALTER TABLE IF EXISTS a ADD b INT, ADD CONSTRAINT a_idx UNIQUE (a)`},
		{`ALTER TABLE IF EXISTS a ADD IF NOT EXISTS b INT, ADD CONSTRAINT a_idx UNIQUE (a)`},
		{`ALTER TABLE a ADD COLUMN b INT, ADD CONSTRAINT a_idx UNIQUE (a)`},
		{`ALTER TABLE a ADD COLUMN IF NOT EXISTS b INT, ADD CONSTRAINT a_idx UNIQUE (a)`},
		{`ALTER TABLE IF EXISTS a ADD COLUMN b INT, ADD CONSTRAINT a_idx UNIQUE (a)`},
		{`ALTER TABLE IF EXISTS a ADD COLUMN IF NOT EXISTS b INT, ADD CONSTRAINT a_idx UNIQUE (a)`},
	}
	for _, d := range testData {
		stmts, err := ParseTraditional(d.sql)
		if err != nil {
			t.Fatalf("%s: expected success, but found %s", d.sql, err)
		}
		s := stmts.String()
		if d.sql != s {
			t.Errorf("expected %s, but found %s", d.sql, s)
		}
	}
}

// TestParse2 verifies that we can parse the supplied SQL and regenerate the
// expected SQL string from the syntax tree. Note that if the input and output
// SQL strings are the same, the test case should go in TestParse instead.
func TestParse2(t *testing.T) {
	testData := []struct {
		sql      string
		expected string
	}{
		{`CREATE INDEX ON a (b ASC, c DESC)`, `CREATE INDEX ON a (b, c)`},
		{`CREATE TABLE a (b INT, UNIQUE INDEX foo (b))`,
			`CREATE TABLE a (b INT, CONSTRAINT foo UNIQUE (b))`},
		{`CREATE INDEX ON a (b) COVERING (c)`, `CREATE INDEX ON a (b) STORING (c)`},

		{`SELECT BOOL 'foo'`, `SELECT CAST('foo' AS BOOL)`},
		{`SELECT INT 'foo'`, `SELECT CAST('foo' AS INT)`},
		{`SELECT REAL 'foo'`, `SELECT CAST('foo' AS REAL)`},
		{`SELECT DECIMAL 'foo'`, `SELECT CAST('foo' AS DECIMAL)`},
		{`SELECT DATE 'foo'`, `SELECT CAST('foo' AS DATE)`},
		{`SELECT TIMESTAMP 'foo'`, `SELECT CAST('foo' AS TIMESTAMP)`},
		{`SELECT INTERVAL 'foo'`, `SELECT CAST('foo' AS INTERVAL)`},
		{`SELECT CHAR 'foo'`, `SELECT CAST('foo' AS CHAR)`},

		{`SELECT 0xf0 FROM t`, `SELECT 240 FROM t`},
		{`SELECT 0xF0 FROM t`, `SELECT 240 FROM t`},
		// Escaped string literals are not always escaped the same because
		// '''' and e'\'' scan to the same token. It's more convenient to
		// prefer escaping ' and \, so we do that.
		{`SELECT 'a''a'`,
			`SELECT e'a\'a'`},
		{`SELECT 'a\a'`,
			`SELECT e'a\\a'`},
		{`SELECT 'a\n'`,
			`SELECT e'a\\n'`},
		{"SELECT '\n'",
			`SELECT e'\n'`},
		{"SELECT '\n\\'",
			`SELECT e'\n\\'`},
		{`SELECT "a'a" FROM t`,
			`SELECT "a'a" FROM t`},
		// Comments are stripped.
		{`SELECT 1 FROM t -- hello world`,
			`SELECT 1 FROM t`},
		{`SELECT /* hello world */ 1 FROM t`,
			`SELECT 1 FROM t`},
		{`SELECT /* hello */ 1 FROM /* world */ t`,
			`SELECT 1 FROM t`},
		// Alias expressions are always output using AS.
		{`SELECT 1 FROM t t1`,
			`SELECT 1 FROM t AS t1`},
		// Alternate not-equal operator.
		{`SELECT FROM t WHERE a <> b`,
			`SELECT FROM t WHERE a != b`},
		// OUTER is syntactic sugar.
		{`SELECT FROM t1 LEFT OUTER JOIN t2 ON a = b`,
			`SELECT FROM t1 LEFT JOIN t2 ON a = b`},
		{`SELECT FROM t1 RIGHT OUTER JOIN t2 ON a = b`,
			`SELECT FROM t1 RIGHT JOIN t2 ON a = b`},
		// TODO(pmattis): Handle UNION ALL.
		{`SELECT FROM t UNION ALL SELECT 1 FROM t`,
			`SELECT FROM t UNION SELECT 1 FROM t`},
		// We allow OFFSET before LIMIT, but always output LIMIT first.
		{`SELECT FROM t OFFSET a LIMIT b`,
			`SELECT FROM t LIMIT b OFFSET a`},
		// Shorthand type cast.
		{`SELECT '1'::INT`,
			`SELECT CAST('1' AS INT)`},
		// Double negation. See #1800.
		{`SELECT *,-/* comment */-5`,
			`SELECT *, - - 5`},
		{"SELECT -\n-5",
			`SELECT - - 5`},
		{`SELECT -0.-/*test*/-1`,
			`SELECT - 0. - - 1`,
		},
		// See #1948.
		{`SELECT~~+~++~bd(*)`,
			`SELECT ~ ~ + ~ + + ~ bd(*)`},
		// See #1957.
		{`SELECT+y[array[]]`,
			`SELECT + y[ARRAY[]]`},
		{`SELECT(0)FROM y[array[]]`,
			`SELECT (0) FROM y[ARRAY[]]`},
	}
	for _, d := range testData {
		stmts, err := ParseTraditional(d.sql)
		if err != nil {
			t.Fatalf("%s: expected success, but found %s", d.sql, err)
		}
		s := stmts.String()
		if d.expected != s {
			t.Errorf("expected %s, but found %s", d.expected, s)
		}
		if _, err := ParseTraditional(s); err != nil {
			t.Errorf("expected string found, but not parsable: %s:\n%s", err, s)
		}
	}
}

// TestParseSyntax verifieds that parsing succeeds, though the syntax tree
// likely differs. All of the test cases here should eventually be moved
// elsewhere.
func TestParseSyntax(t *testing.T) {
	testData := []struct {
		sql string
	}{
		{`SELECT '\0' FROM a`},
		{`SELECT ((1)) FROM t WHERE ((a)) IN (((1))) AND ((a, b)) IN ((((1, 1))), ((2, 2)))`},
		{`SELECT e'\'\"\b\n\r\t\\' FROM t`},
		{`SELECT '\x' FROM t`},
		{`SELECT 1 FROM t GROUP BY a`},
		{`DROP INDEX a`},
		{`DROP INDEX IF EXISTS a`},
	}
	for _, d := range testData {
		if _, err := ParseTraditional(d.sql); err != nil {
			t.Fatalf("%s: expected success, but not parsable %s", d.sql, err)
		}
	}
}

func TestParseError(t *testing.T) {
	testData := []struct {
		sql      string
		expected string
	}{
		{`SELECT2 1`, `syntax error at or near "SELECT2"
SELECT2 1
^
`},
		{`SELECT 1 FROM (t)`, `syntax error at or near ")"
SELECT 1 FROM (t)
                ^
`},
		{`SET a = 1, b = 2`, `syntax error at or near "="
SET a = 1, b = 2
             ^
`},
		{`SET a = 1,
b = 2`, `syntax error at or near "="
SET a = 1,
b = 2
  ^
`},
		{`SELECT 1 /* hello`, `unterminated comment
SELECT 1 /* hello
         ^
`},
		{`SELECT '1`, `unterminated string
SELECT '1
       ^
`},
		{`CREATE TABLE test (
  CONSTRAINT foo INDEX (bar)
)`, `syntax error at or near "INDEX"
CREATE TABLE test (
  CONSTRAINT foo INDEX (bar)
                 ^
`},
		{`CREATE DATABASE a b`,
			`syntax error at or near "b"
CREATE DATABASE a b
                  ^
`},
		{`CREATE DATABASE a b c`,
			`syntax error at or near "b"
CREATE DATABASE a b c
                  ^
`},
		{`CREATE INDEX ON a (b) STORING ()`,
			`syntax error at or near ")"
CREATE INDEX ON a (b) STORING ()
                               ^
`},
		{"SELECT 1e-\n-1",
			`invalid floating point literal
SELECT 1e-
       ^
`},
		{"SELECT foo''",
			`syntax error at or near ""
SELECT foo''
          ^
`},
		{
			`SELECT 0x FROM t`,
			`invalid hexadecimal literal
SELECT 0x FROM t
       ^
`,
		},
	}
	for _, d := range testData {
		_, err := ParseTraditional(d.sql)
		if err == nil || err.Error() != d.expected {
			t.Fatalf("%s: expected\n%s, but found\n%v", d.sql, d.expected, err)
		}
	}
}

func TestParsePanic(t *testing.T) {
	// Replicates #1801.
	defer func() {
		if r := recover(); r != nil {
			t.Fatal(r)
		}
	}()
	s := "SELECT(F(F(F(F(F(F(F" +
		"(F(F(F(F(F(F(F(F(F(F" +
		"(F(F(F(F(F(F(F(F(F(F" +
		"(F(F(F(F(F(F(F(F(F(F" +
		"(F(F(F(F(F(F(F(F(F(T" +
		"(F(F(F(F(F(F(F(F(F(F" +
		"(F(F(F(F(F(F(F(F(F(F" +
		"(F(F(F(F(F(F(F(F(F(F" +
		"(F(F(F(F(F(F(F(F(F(F" +
		"(F(F(F(F(F(F(F(F(F((" +
		"F(0"
	_, err := ParseTraditional(s)
	expected := `syntax error at or near "EOF"`
	if !testutils.IsError(err, expected) {
		t.Fatalf("expected %s, but found %v", expected, err)
	}
}

func TestParsePrecedence(t *testing.T) {
	// Precedence levels (highest first):
	//   0: - ~
	//   1: * / %
	//   2: + -
	//   3: << >>
	//   4: &
	//   5: ^
	//   6: |
	//   7: = != > >= < <=
	//   8: NOT
	//   9: AND
	//  10: OR

	unary := func(op UnaryOp, expr Expr) Expr {
		return &UnaryExpr{Operator: op, Expr: expr}
	}
	binary := func(op BinaryOp, left, right Expr) Expr {
		return &BinaryExpr{Operator: op, Left: left, Right: right}
	}
	cmp := func(op ComparisonOp, left, right Expr) Expr {
		return &ComparisonExpr{Operator: op, Left: left, Right: right}
	}
	not := func(expr Expr) Expr {
		return &NotExpr{Expr: expr}
	}
	and := func(left, right Expr) Expr {
		return &AndExpr{Left: left, Right: right}
	}
	or := func(left, right Expr) Expr {
		return &OrExpr{Left: left, Right: right}
	}

	one := IntVal(1)
	two := IntVal(2)
	three := IntVal(3)

	testData := []struct {
		sql      string
		expected Expr
	}{
		// Unary plus and complement.
		{`~-1`, unary(UnaryComplement, unary(UnaryMinus, one))},
		{`-~1`, unary(UnaryMinus, unary(UnaryComplement, one))},

		// Mul, div, mod combined with higher precedence.
		{`-1*2`, binary(Mult, unary(UnaryMinus, one), two)},
		{`1*-2`, binary(Mult, one, unary(UnaryMinus, two))},
		{`-1/2`, binary(Div, unary(UnaryMinus, one), two)},
		{`1/-2`, binary(Div, one, unary(UnaryMinus, two))},
		{`-1%2`, binary(Mod, unary(UnaryMinus, one), two)},
		{`1%-2`, binary(Mod, one, unary(UnaryMinus, two))},

		// Mul, div, mod combined with self (left associative).
		{`1*2*3`, binary(Mult, binary(Mult, one, two), three)},
		{`1*2/3`, binary(Div, binary(Mult, one, two), three)},
		{`1/2*3`, binary(Mult, binary(Div, one, two), three)},
		{`1*2%3`, binary(Mod, binary(Mult, one, two), three)},
		{`1%2*3`, binary(Mult, binary(Mod, one, two), three)},
		{`1/2/3`, binary(Div, binary(Div, one, two), three)},
		{`1/2*3`, binary(Mult, binary(Div, one, two), three)},
		{`1/2%3`, binary(Mod, binary(Div, one, two), three)},
		{`1%2/3`, binary(Div, binary(Mod, one, two), three)},
		{`1%2%3`, binary(Mod, binary(Mod, one, two), three)},

		// Binary plus and minus combined with higher precedence.
		{`1*2+3`, binary(Plus, binary(Mult, one, two), three)},
		{`1+2*3`, binary(Plus, one, binary(Mult, two, three))},
		{`1*2-3`, binary(Minus, binary(Mult, one, two), three)},
		{`1-2*3`, binary(Minus, one, binary(Mult, two, three))},

		// Binary plus and minus combined with self (left associative).
		{`1+2-3`, binary(Minus, binary(Plus, one, two), three)},
		{`1-2+3`, binary(Plus, binary(Minus, one, two), three)},

		// Left and right shift combined with higher precedence.
		{`1<<2+3`, binary(LShift, one, binary(Plus, two, three))},
		{`1+2<<3`, binary(LShift, binary(Plus, one, two), three)},
		{`1>>2+3`, binary(RShift, one, binary(Plus, two, three))},
		{`1+2>>3`, binary(RShift, binary(Plus, one, two), three)},

		// Left and right shift combined with self (left associative).
		{`1<<2<<3`, binary(LShift, binary(LShift, one, two), three)},
		{`1<<2>>3`, binary(RShift, binary(LShift, one, two), three)},
		{`1>>2<<3`, binary(LShift, binary(RShift, one, two), three)},
		{`1>>2>>3`, binary(RShift, binary(RShift, one, two), three)},

		// Bit-and combined with higher precedence.
		{`1&2<<3`, binary(Bitand, one, binary(LShift, two, three))},
		{`1<<2&3`, binary(Bitand, binary(LShift, one, two), three)},

		// Bit-and combined with self (left associative)
		{`1&2&3`, binary(Bitand, binary(Bitand, one, two), three)},

		// Bit-xor combined with higher precedence.
		{`1^2&3`, binary(Bitxor, one, binary(Bitand, two, three))},
		{`1&2^3`, binary(Bitxor, binary(Bitand, one, two), three)},

		// Bit-xor combined with self (left associative)
		{`1^2^3`, binary(Bitxor, binary(Bitxor, one, two), three)},

		// Bit-or combined with higher precedence.
		{`1|2^3`, binary(Bitor, one, binary(Bitxor, two, three))},
		{`1^2|3`, binary(Bitor, binary(Bitxor, one, two), three)},

		// Bit-or combined with self (left associative)
		{`1|2|3`, binary(Bitor, binary(Bitor, one, two), three)},

		// Equals, not-equals, greater-than, greater-than equals, less-than and
		// less-than equals combined with higher precedence.
		{`1 = 2|3`, cmp(EQ, one, binary(Bitor, two, three))},
		{`1|2 = 3`, cmp(EQ, binary(Bitor, one, two), three)},
		{`1 != 2|3`, cmp(NE, one, binary(Bitor, two, three))},
		{`1|2 != 3`, cmp(NE, binary(Bitor, one, two), three)},
		{`1 > 2|3`, cmp(GT, one, binary(Bitor, two, three))},
		{`1|2 > 3`, cmp(GT, binary(Bitor, one, two), three)},
		{`1 >= 2|3`, cmp(GE, one, binary(Bitor, two, three))},
		{`1|2 >= 3`, cmp(GE, binary(Bitor, one, two), three)},
		{`1 < 2|3`, cmp(LT, one, binary(Bitor, two, three))},
		{`1|2 < 3`, cmp(LT, binary(Bitor, one, two), three)},
		{`1 <= 2|3`, cmp(LE, one, binary(Bitor, two, three))},
		{`1|2 <= 3`, cmp(LE, binary(Bitor, one, two), three)},

		// NOT combined with higher precedence.
		{`NOT 1 = 2`, not(cmp(EQ, one, two))},
		{`NOT 1 = NOT 2 = 3`, not(cmp(EQ, one, not(cmp(EQ, two, three))))},

		// NOT combined with self.
		{`NOT NOT 1 = 2`, not(not(cmp(EQ, one, two)))},

		// AND combined with higher precedence.
		{`NOT 1 AND 2`, and(not(one), two)},
		{`1 AND NOT 2`, and(one, not(two))},

		// AND combined with self (left associative).
		{`1 AND 2 AND 3`, and(and(one, two), three)},

		// OR combined with higher precedence.
		{`1 AND 2 OR 3`, or(and(one, two), three)},
		{`1 OR 2 AND 3`, or(one, and(two, three))},

		// OR combined with self (left associative).
		{`1 OR 2 OR 3`, or(or(one, two), three)},
	}
	for _, d := range testData {
		q, err := ParseTraditional("SELECT " + d.sql)
		if err != nil {
			t.Fatalf("%s: %v", d.sql, err)
		}
		expr := q[0].(*Select).Exprs[0].Expr
		if !reflect.DeepEqual(d.expected, expr) {
			t.Fatalf("%s: expected %s, but found %s", d.sql, d.expected, expr)
		}
	}
}
