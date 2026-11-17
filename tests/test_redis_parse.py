# tests/test_redis_parse.py

from nope.decoys.redis import classify, parse_command

# ================================
#   Redis command parsing and classification
# ================================


# Check that a RESP AUTH request exposes both the command and its argument
def test_resp_auth_is_classified_as_auth():
    request = b"*2\r\n$4\r\nAUTH\r\n$6\r\nhunter\r\n"

    command_words = parse_command(request)
    assert command_words == ["AUTH", "hunter"]  # RESP array and string markers are removed
    assert classify(command_words) == "auth"


# Check that a plain-text PING counts as a probe
def test_inline_ping_is_probe():
    request = b"PING\r\n"  # Inline requests have no RESP array or string markers
    assert classify(parse_command(request)) == "probe"


# Check that a request to change Redis settings counts as an exploit
def test_config_set_is_exploit():
    # CONFIG SET dir /tmp/ attempts to change the Redis working directory
    request = b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$5\r\n/tmp/\r\n"
    assert classify(parse_command(request)) == "exploit"


# Check that exploit classification takes priority over authentication
def test_exploit_wins_over_auth_in_a_pipeline():
    request = (
        b"*2\r\n$4\r\nAUTH\r\n$1\r\nx\r\n"  # AUTH arrives first
        b"*3\r\n$7\r\nSLAVEOF\r\n$1\r\n1\r\n$1\r\n2\r\n"  # SLAVEOF follows in the same read
    )

    assert classify(parse_command(request)) == "exploit"
