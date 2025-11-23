# Tests

This directory contains tests for the Squid Whitelist Proxy appliance.

## Test Files

### `test_empty_whitelist.sh`
Integration test that verifies the container starts successfully with an empty whitelist.

**What it tests:**
- Container starts without errors when whitelist is empty
- Health endpoint responds
- Proxy denies all traffic (correct "deny all" behavior)
- No restart loop occurs

**Run it:**
```bash
cd /path/to/squidlyfe
./tests/test_empty_whitelist.sh
```

**Expected outcome:**
- Container starts and stays running
- Health check passes: `curl http://localhost:8080/health` returns 200
- Proxy requests are denied: `curl -x http://localhost:3128 http://example.com` returns 403

### `test_whitelist_validation.py`
Unit tests for whitelist read/write operations.

**What it tests:**
- Reading empty whitelist returns empty list (not an error)
- Reading whitelist with only comments returns empty list
- Writing empty whitelist creates valid file
- Round-trip write-then-read preserves entries
- Empty entries are filtered out

**Run it:**
```bash
cd /path/to/squidlyfe
python3 tests/test_whitelist_validation.py
```

**Expected outcome:**
```
test_empty_entries_filtered (__main__.TestWhitelistValidation) ... ok
test_read_empty_whitelist (__main__.TestEmptyWhitelistHandling) ... ok
test_read_whitelist_mixed_content (__main__.TestEmptyWhitelistHandling) ... ok
test_read_whitelist_only_comments (__main__.TestEmptyWhitelistHandling) ... ok
test_write_empty_whitelist (__main__.TestEmptyWhitelistHandling) ... ok
test_write_then_read_whitelist (__main__.TestEmptyWhitelistHandling) ... ok

----------------------------------------------------------------------
Ran 6 tests in X.XXXs

OK
```

## Running All Tests

```bash
# Unit tests
python3 tests/test_whitelist_validation.py

# Integration test (requires Docker)
./tests/test_empty_whitelist.sh
```

## Adding New Tests

When adding features, please add corresponding tests:

1. **Unit tests** (Python): Add to `test_whitelist_validation.py` or create new test files
2. **Integration tests** (Bash): Create new `.sh` scripts in this directory

## Test Coverage

Current test coverage focuses on the empty whitelist regression:

- ✅ Empty whitelist file handling
- ✅ Whitelist with only comments
- ✅ Container startup with empty whitelist
- ✅ Health check with empty whitelist
- ✅ Proxy deny-all behavior

Future test areas:
- [ ] Web UI login and authentication
- [ ] Whitelist add/remove via UI
- [ ] Logging configuration changes
- [ ] Squid reload on configuration change
- [ ] Multi-user scenarios (future feature)
