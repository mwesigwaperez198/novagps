import pytest

from schemas import LocationUpdateRequest


def test_location_requires_device_or_identifier():
    with pytest.raises(ValueError):
        LocationUpdateRequest(latitude=1, longitude=1)


def test_location_accepts_identifier():
    payload = LocationUpdateRequest(identifier="android-001", latitude=1, longitude=1)
    assert payload.identifier == "android-001"
