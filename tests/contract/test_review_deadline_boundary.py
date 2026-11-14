"""The review deadline is inclusive and fails closed without a deadline.

The integration race tests prove that a *past* deadline expires a review, but
their two ``clock_timestamp()`` calls always advance, so they cannot produce
``deadline == decision_at``. This contract test pins the shared predicate that
both review paths use, including the exact equality boundary and the
microsecond on either side of it.
"""

from datetime import datetime, timedelta, timezone

import pytest

from datacon.state import _review_window_closed

DECISION_AT = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("deadline", "expected"),
    [
        (DECISION_AT, True),
        (DECISION_AT - timedelta(microseconds=1), True),
        (DECISION_AT + timedelta(microseconds=1), False),
        (None, True),
    ],
)
def test_review_window_boundary(deadline, expected):
    assert _review_window_closed(deadline, DECISION_AT) is expected


def test_review_window_is_inclusive_across_a_microsecond_range():
    """Pin the inclusive comparison, not merely ``deadline < decision_at``."""
    instants = [
        DECISION_AT + timedelta(microseconds=offset) for offset in range(-3, 4)
    ]
    closed = [
        instant
        for instant in instants
        if _review_window_closed(instant, DECISION_AT)
    ]
    assert closed == [
        DECISION_AT + timedelta(microseconds=offset) for offset in range(-3, 1)
    ]
