"""Redmine read-only source: how the user list resolves email addresses.

Redmine 3.0 moved the authoritative address from `users.mail` into the
`email_addresses` table. Databases upgraded across that boundary usually keep
the old column, unmaintained - so accounts created afterwards have an address
in the Redmine UI and an empty `users.mail`. Reading the column alone made
those users unmappable ("kein Redmine-Benutzer") even though their address
matched their LDAP one exactly.
"""

import pytest

from aw_server.redmine import RedmineReadOnlyError, RedmineReadOnlySource


class RecordingSource(RedmineReadOnlySource):
    """A source whose _query is scripted instead of hitting a database."""

    def __init__(self, responses, config=None):
        super().__init__(config or {})
        # responses: list of either row-lists to return or exceptions to raise.
        self.responses = list(responses)
        self.queries = []

    def _query(self, sql, params=None):
        self._assert_select_only(sql)
        self.queries.append(sql)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _rows(*mails):
    return [
        {
            "id": index + 1,
            "login": f"user{index}",
            "firstname": "F",
            "lastname": "L",
            "mail": mail,
        }
        for index, mail in enumerate(mails)
    ]


def test_active_users_reads_the_email_addresses_table():
    source = RecordingSource([_rows("E.Causevic@tbfgmbh.at")])

    users = source.active_users()

    assert len(source.queries) == 1
    sql = source.queries[0]
    assert "email_addresses" in sql
    assert "is_default" in sql
    # users.mail is only the fallback, never the primary read.
    assert "COALESCE" in sql
    assert users[0]["mail"] == "e.causevic@tbfgmbh.at"


def test_active_users_falls_back_when_email_addresses_is_missing():
    """Redmine older than 3.0 has no email_addresses table."""
    missing = RedmineReadOnlyError(
        "Redmine tables were not found.", code="redmine_table_missing"
    )
    source = RecordingSource([missing, _rows("old@example.at")])

    users = source.active_users()

    assert len(source.queries) == 2
    assert "email_addresses" in source.queries[0]
    assert "email_addresses" not in source.queries[1]
    assert "u.mail" in source.queries[1]
    assert users[0]["mail"] == "old@example.at"


def test_active_users_falls_back_when_users_mail_was_dropped():
    """A clean Redmine 3.0+ install has no users.mail column."""
    dropped = RedmineReadOnlyError(
        "Redmine returned an unexpected table layout.",
        code="redmine_schema_mismatch",
    )
    source = RecordingSource([dropped, _rows("new@example.at")])

    users = source.active_users()

    assert len(source.queries) == 2
    assert "email_addresses" in source.queries[1]
    assert "u.mail" not in source.queries[1]
    assert users[0]["mail"] == "new@example.at"


def test_active_users_does_not_swallow_unrelated_errors():
    """A connection failure must surface, not silently retry a variant."""
    unreachable = RedmineReadOnlyError(
        "Redmine database is not reachable.", code="redmine_connection_failed"
    )
    source = RecordingSource([unreachable])

    with pytest.raises(RedmineReadOnlyError) as excinfo:
        source.active_users()

    assert excinfo.value.code == "redmine_connection_failed"
    assert len(source.queries) == 1


def test_active_users_query_is_select_only_in_every_variant():
    """The generated SQL must pass the read-only guard in all three shapes."""
    source = RedmineReadOnlySource({})
    for email_table, mail_column in ((True, True), (True, False), (False, True)):
        sql = source._active_users_sql(
            "", email_table=email_table, mail_column=mail_column
        )
        source._assert_select_only(sql)


def test_active_users_honours_the_table_prefix_on_email_addresses():
    source = RecordingSource([_rows("x@example.at")], config={"table_prefix": "rm_"})

    source.active_users()

    assert "`rm_email_addresses`" in source.queries[0]
    assert "`rm_users`" in source.queries[0]


def test_active_users_applies_the_limit():
    source = RecordingSource([_rows("x@example.at")])

    source.active_users(limit=1)

    assert "LIMIT 1" in source.queries[0]


def test_active_users_normalizes_a_missing_address_to_empty():
    """A user with no address anywhere stays empty rather than becoming 'None'."""
    source = RecordingSource([_rows(None)])

    users = source.active_users()

    assert users[0]["mail"] == ""
