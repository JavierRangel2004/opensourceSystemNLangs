package edu.up.wazuh.events;

import edu.up.wazuh.model.Alert;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertParserTest {

    private final AlertParser parser = new AlertParser();

    @Test
    void parses_root_alert_with_level_agent_rule_and_timestamp() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51.123+0000",
                  "rule": {"level": 12, "description": "Test", "id": "5700"},
                  "agent": {"id": "001", "name": "host1"},
                  "id": "alert-1"
                }
                """;
        Alert a = parser.parse(json);
        assertEquals("alert-1", a.id());
        assertEquals(Instant.parse("2024-09-23T14:28:51.123Z"), a.timestamp());
        assertEquals("001", a.agentId());
        assertEquals("host1", a.agentName());
        assertEquals("5700", a.ruleId());
        assertEquals(12, a.level());
        assertEquals("Test", a.description());
        assertNull(a.latitude());
        assertNull(a.longitude());
    }

    @Test
    void parses_envelope_under_alert_key() {
        String json = """
                {
                  "integration": "custom-dashboard",
                  "alert": {
                    "timestamp": "2024-09-23T14:28:51Z",
                    "rule": {"level": 5, "id": "5500"},
                    "agent": {"id": "002"}
                  }
                }
                """;
        Alert a = parser.parse(json);
        assertEquals("002", a.agentId());
        assertEquals("5500", a.ruleId());
        assertEquals(5, a.level());
        assertEquals("custom-dashboard", a.integration());
    }

    @Test
    void extracts_unix_srcuser_dstuser_user() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {"srcuser": "alice", "dstuser": "bob"}
                }
                """;
        assertEquals("alice", parser.parse(json).username());

        String json2 = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {"user": "carol"}
                }
                """;
        assertEquals("carol", parser.parse(json2).username());
    }

    @Test
    void extracts_windows_targetUserName_with_domain() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "win": {"eventdata": {"targetUserName": "ACME\\\\jdoe"}}
                }
                """;
        Alert a = parser.parse(json);
        assertEquals("ACME\\jdoe", a.username());
    }

    @Test
    void extracts_windows_subjectUserName() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "win": {"eventdata": {"subjectUserName": "ACME\\\\admin"}}
                }
                """;
        assertEquals("ACME\\admin", parser.parse(json).username());
    }

    @Test
    void captures_virustotal_integration_field() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 10, "id": "87100"},
                  "agent": {"id": "001"},
                  "integration": "virustotal",
                  "data": {"virustotal": {"source": {"file": "x.bin"}, "positives": 5}}
                }
                """;
        Alert a = parser.parse(json);
        assertEquals("virustotal", a.integration());
        // Description is empty because VirusTotal data is not part of description.
        assertEquals("", a.description());
    }

    @Test
    void parses_geolocation_and_country() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "geoLocation": {"latitude": "12.5", "longitude": "-56.7", "country_name": "AR"}
                }
                """;
        Alert a = parser.parse(json);
        assertEquals(12.5, a.latitude());
        assertEquals(-56.7, a.longitude());
        assertEquals("AR", a.country());
    }

    @Test
    void tolerates_missing_geolocation() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        Alert a = parser.parse(json);
        assertNull(a.latitude());
        assertNull(a.longitude());
        assertEquals("", a.country());
    }

    @Test
    void falls_back_to_deterministic_id_when_missing() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        Alert a = parser.parse(json);
        Alert b = parser.parse(json);
        assertEquals(a.id(), b.id());
        assertEquals(32, a.id().length());

        String jsonOther = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5501"},
                  "agent": {"id": "001"}
                }
                """;
        assertNotEquals(a.id(), parser.parse(jsonOther).id());
    }

    @Test
    void rejects_invalid_json() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse("{not json"));
    }

    @Test
    void rejects_missing_timestamp() {
        String json = """
                {
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(json));
    }

    @Test
    void rejects_invalid_timestamp() {
        String json = """
                {
                  "timestamp": "not a date",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(json));
    }

    @Test
    void rejects_out_of_range_severity() {
        String tooHigh = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 16, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(tooHigh));

        String neg = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": -1, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(neg));
    }

    @Test
    void accepts_severity_boundary_values() {
        String zero = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 0, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        assertEquals(0, parser.parse(zero).level());

        String fifteen = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 15, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        assertEquals(15, parser.parse(fifteen).level());
    }

    @Test
    void rejects_invalid_coordinates() {
        String badLat = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "geoLocation": {"latitude": "91", "longitude": "0"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(badLat));

        String badLon = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "geoLocation": {"latitude": "0", "longitude": "-181"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(badLon));
    }

    @Test
    void rejects_missing_rule() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "agent": {"id": "001"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(json));
    }

    @Test
    void does_not_store_full_log_field() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "full_log": "very secret payload that must not leak"
                }
                """;
        Alert a = parser.parse(json);
        assertTrue(!a.description().contains("very secret")
                && !a.description().contains("payload"),
                "description must not include full_log");
    }

    @Test
    void rejects_fractional_severity_number() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 12.5, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(json));
    }

    @Test
    void rejects_severity_overflow() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 99999999999, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(json));
    }

    @Test
    void rejects_non_integer_severity_string() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": "12.5", "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        assertThrows(IllegalArgumentException.class, () -> parser.parse(json));
    }

    @Test
    void extracts_windows_targetUserName_via_data_win_eventdata() {
        // Real Wazuh indexer/manager payload nests Windows fields under data.win.
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {
                    "win": {
                      "eventdata": {"targetUserName": "alice"}
                    }
                  }
                }
                """;
        assertEquals("alice", parser.parse(json).username());
    }

    @Test
    void preserves_domain_from_targetDomainName_eventdata() {
        // Windows events often arrive with targetUserName and targetDomainName
        // as separate fields; preserve the original DOMAIN-backslash-user identity so
        // the LDAP filter can match against sAMAccountName.
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {
                    "win": {
                      "eventdata": {
                        "targetUserName": "jdoe",
                        "targetDomainName": "ACME"
                      }
                    }
                  }
                }
                """;
        assertEquals("ACME" + "\\" + "jdoe", parser.parse(json).username());
    }

    @Test
    void preserves_domain_from_subjectDomainName() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {
                    "win": {
                      "eventdata": {
                        "subjectUserName": "svc-backup",
                        "subjectDomainName": "BUILTIN"
                      }
                    }
                  }
                }
                """;
assertEquals("BUILTIN" + "\\" + "svc-backup",
                parser.parse(json).username());
    }

    @Test
    void does_not_double_already_prefixed_username() {
        // If the payload already contains DOMAIN-backslash-user, don't prepend again.
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {
                    "win": {
                      "eventdata": {
                        "targetUserName": "ACME\\\\jdoe",
                        "targetDomainName": "OTHER"
                      }
                    }
                  }
                }
                """;
        // Java string source "ACME\\jdoe" == 1 backslash, matching the parser
        // output for that already-prefixed input.
        assertEquals("ACME" + "\\" + "jdoe", parser.parse(json).username());
    }

    @Test
    void placeholder_dash_in_srcuser_does_not_stop_later_fields() {
        // If the first username slot is just the placeholder "-", the parser
        // must keep looking at later fields. Only after all candidate slots
        // have been checked should it give up.
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {"srcuser": "-", "dstuser": "alice"}
                }
                """;
        assertEquals("alice", parser.parse(json).username());

        String jsonWin = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {
                    "srcuser": "-",
                    "win": {"eventdata": {"targetUserName": "bob"}}
                  }
                }
                """;
        assertEquals("bob", parser.parse(jsonWin).username());
    }

    @Test
    void parses_indexer_style_GeoLocation_capitalized() {
        // Real Wazuh indexer emits the geographic block with capital G;
        // manager alerts use the lower-case spelling. Both must work.
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "GeoLocation": {
                    "city_name": "Panama City",
                    "country_name": "PA",
                    "latitude": 8.9824,
                    "longitude": -79.5199
                  }
                }
                """;
        Alert a = parser.parse(json);
        assertEquals(8.9824, a.latitude());
        assertEquals(-79.5199, a.longitude());
        assertEquals("PA", a.country());
    }

    @Test
    void parses_geolocation_under_data_block_too() {
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {
                    "GeoLocation": {"latitude": 1.0, "longitude": 2.0, "country_name": "MX"}
                  }
                }
                """;
        Alert a = parser.parse(json);
        assertEquals(1.0, a.latitude());
        assertEquals(2.0, a.longitude());
        assertEquals("MX", a.country());
    }

    @Test
    void parses_indexer_latitude_longitude_capital_keys() {
        // Mixed casing inside the geo block must still work.
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "GeoLocation": {"Latitude": "5.1", "Longitude": "-3.2"}
                }
                """;
        Alert a = parser.parse(json);
        assertEquals(5.1, a.latitude());
        assertEquals(-3.2, a.longitude());
    }

    @Test
    void deterministic_id_distinguishes_alerts_with_same_agent_rule_and_instant() {
        // Two events that share agentId, ruleId and timestamp but differ on
        // username must get different IDs so the EventStore can dedupe them
        // independently.
        String bare = """
                {
                  "timestamp": "2024-09-23T14:28:51.123Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"}
                }
                """;
        String aliceJson = """
                {
                  "timestamp": "2024-09-23T14:28:51.123Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {"user": "alice"}
                }
                """;
        String bobJson = """
                {
                  "timestamp": "2024-09-23T14:28:51.123Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {"user": "bob"}
                }
                """;
        Alert bare1 = parser.parse(bare);
        Alert alice = parser.parse(aliceJson);
        Alert bob = parser.parse(bobJson);
        assertNotEquals(alice.id(), bob.id(),
                "distinct events at the same instant must get distinct IDs");
        // Sanity: the bare template alert still has a stable ID.
        Alert bare2 = parser.parse(bare);
        assertEquals(bare1.id(), bare2.id());
    }

    @Test
    void windows_eventdata_placeholder_target_falls_back_to_subject() {
        // Real Windows events sometimes ship with targetUserName="-"
        // (placeholder) and the actual identity in subjectUserName.
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {
                    "win": {
                      "eventdata": {
                        "targetUserName": "-",
                        "targetDomainName": "ACME",
                        "subjectUserName": "real-user",
                        "subjectDomainName": "BUILTIN"
                      }
                    }
                  }
                }
                """;
        // The user and domain must be paired: subject user with subject
        // domain, not mixed.
        assertEquals("BUILTIN" + "\\" + "real-user",
                parser.parse(json).username());
    }

    @Test
    void windows_eventdata_dash_domain_is_not_used_as_prefix() {
        // A placeholder "-" in the domain field must not be prefixed onto
        // the user; the resulting identity is the bare user.
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {
                    "win": {
                      "eventdata": {
                        "targetUserName": "alice",
                        "targetDomainName": "-"
                      }
                    }
                  }
                }
                """;
        assertEquals("alice", parser.parse(json).username());
    }

    @Test
    void windows_eventdata_uses_only_paired_user_and_domain() {
        // Mixing targetUserName with subjectDomainName would mis-correlate.
        String json = """
                {
                  "timestamp": "2024-09-23T14:28:51Z",
                  "rule": {"level": 5, "id": "5500"},
                  "agent": {"id": "001"},
                  "data": {
                    "win": {
                      "eventdata": {
                        "targetUserName": "alice",
                        "targetDomainName": "ACME",
                        "subjectDomainName": "OTHER"
                      }
                    }
                  }
                }
                """;
        assertEquals("ACME" + "\\" + "alice",
                parser.parse(json).username());
    }
}
