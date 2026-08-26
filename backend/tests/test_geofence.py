import pytest

from worker.geofence import (
    DEFAULT_GEOFENCES,
    check_event_against_geofences_local,
    parse_wkt_polygon,
    point_in_polygon_wkt,
    list_geofences_as_dicts,
)


def test_default_geofences_exist():
    assert len(DEFAULT_GEOFENCES) > 0


def test_point_inside_demo_fence():
    matches = check_event_against_geofences_local("dev1", -122.41, 37.78)
    assert len(matches) == 1
    assert matches[0]["geofence_id"] == "demo-nova-hq"


def test_point_outside_fence():
    matches = check_event_against_geofences_local("dev1", 0.0, 0.0)
    assert matches == []


def test_point_on_boundary():
    matches = check_event_against_geofences_local("dev1", -122.42, 37.77)
    assert isinstance(matches, list)


def test_parse_wkt_polygon():
    coords = parse_wkt_polygon(DEFAULT_GEOFENCES[0].polygon_wkt)
    assert len(coords) == 5
    assert coords[0]["longitude"] == pytest.approx(-122.42)
    assert coords[0]["latitude"] == pytest.approx(37.77)


def test_list_geofences_as_dicts():
    result = list_geofences_as_dicts()
    assert len(result) > 0
    assert "coords" in result[0]
    assert "polygon_wkt" in result[0]


def test_point_in_polygon_wkt_square():
    polygon = "POLYGON((0 0, 10 0, 10 10, 0 10, 0 0))"
    assert point_in_polygon_wkt(polygon, 5.0, 5.0) is True
    assert point_in_polygon_wkt(polygon, 15.0, 5.0) is False
    assert point_in_polygon_wkt(polygon, 5.0, -1.0) is False


def test_point_in_polygon_wkt_triangle():
    polygon = "POLYGON((0 0, 10 0, 5 10, 0 0))"
    assert point_in_polygon_wkt(polygon, 5.0, 3.0) is True
    assert point_in_polygon_wkt(polygon, 1.0, 1.0) is True
    assert point_in_polygon_wkt(polygon, 15.0, 5.0) is False
    assert point_in_polygon_wkt(polygon, 5.0, -1.0) is False


def test_point_in_polygon_wkt_invalid():
    assert point_in_polygon_wkt("POLYGON()", 0.0, 0.0) is False
    assert point_in_polygon_wkt("POLYGON((1 2))", 0.0, 0.0) is False


def test_multiple_devices_same_location():
    matches1 = check_event_against_geofences_local("dev1", -122.41, 37.78)
    matches2 = check_event_against_geofences_local("dev2", -122.41, 37.78)
    assert matches1[0]["geofence_id"] == matches2[0]["geofence_id"]
